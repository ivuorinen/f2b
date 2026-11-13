# graphify reference: query, path, explain

Load this when the user asks a question against an existing graph, or runs `/graphify path` or `/graphify explain`. The core's query stub points here for the full traversal flow. These flows use the `graphify query` CLI when it is available and fall back to an inline NetworkX traversal otherwise.

Two traversal modes - choose based on the question:

| Mode | Flag | Best for |
|------|------|----------|
| BFS (default) | _(none)_ | "What is X connected to?" - broad context, nearest neighbors first |
| DFS | `--dfs` | "How does X reach Y?" - trace a specific chain or dependency path |

First check the graph exists:
```bash
$(cat graphify-out/.graphify_python) -c "
from pathlib import Path
if not Path('graphify-out/graph.json').exists():
    print('ERROR: No graph found. Run /graphify <path> first to build the graph.')
    raise SystemExit(1)
"
```
If it fails, stop and tell the user to run `/graphify <path>` first.

### Step 0 — Constrained query expansion (REQUIRED before traversal)

graphify's `query` CLI matches nodes via case-folded substring + IDF — there is **no stemming, no synonyms, no cross-language match** inside the binary, and the inline fallback below matches the same way. If the user's question uses different language or different domain vocabulary than the graph's labels (user says "обработчик" / graph says "handler"; user says "authentication" / graph says "Guardian"), the literal matcher returns 0 hits and the answer collapses to noise.

Fix this **without inventing tokens** by expanding the query against the actual graph vocabulary first:

1. Extract the token vocabulary from node labels:
```bash
$(cat graphify-out/.graphify_python) -c "
import json, re
from pathlib import Path
data = json.loads(Path('graphify-out/graph.json').read_text(encoding='utf-8'))
vocab = set()
for n in data['nodes']:
    for c in re.findall(r'[^\W\d_]+', n.get('label','') or '', re.UNICODE):
        parts = re.findall(r'[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+', c) or [c]
        for p in parts:
            t = p.lower()
            if 3 <= len(t) <= 30:
                vocab.add(t)
Path('graphify-out/.vocab.txt').write_text('\n'.join(sorted(vocab)), encoding='utf-8')
print(f'vocab: {len(vocab)} tokens')
"
```

2. Read `graphify-out/.vocab.txt`. Then for the user's question, select **up to 12 tokens from this exact list** that semantically match the query intent. Hard constraints:
   - You MUST pick only tokens present in the vocabulary file. Do NOT invent tokens.
   - If a query concept has no plausible token in the vocab, skip it — do not substitute a near-synonym from training memory.
   - If **no** vocab tokens match the query at all, output an empty list and tell the user the corpus has no relevant vocabulary for this question. Do not fabricate a search.
   - Translate cross-language: Russian "аутентификация" → look for `auth`, `credential`, `token`, `security` IFF present in vocab.
   - Morphology: "handlers" maps to `handler` IFF present; "todos" maps to `todo` IFF present.

3. Print the selection explicitly to the user before running the query, so the expansion is auditable:
```
Query expanded to (from graph vocab, N tokens): [token1, token2, ...]
```
If the list is empty, say so plainly and stop — do not proceed to traversal.

### Step 1 — Traversal

Build the **expanded query string** by joining the selected tokens with spaces. Use this string as the question
below — NOT the original user question. (The original question is preserved only for `save-result` at the end.)

Write the expanded query string to `graphify-out/.graphify_question.txt` with the Write tool, then prefer the CLI
when it is installed:
```bash
# when needed, add the fixed options --dfs and/or --budget 3000 to the first line
# after the closing quote; inside the quotes or the question file they are
# question text and graphify ignores them as options
$(cat graphify-out/.graphify_python) -m graphify query "$(cat graphify-out/.graphify_question.txt)"
rc=$?; rm -f graphify-out/.graphify_question.txt; exit "$rc"
```

If the CLI is unavailable, load `graphify-out/graph.json` and run the traversal inline:

1. Find the 1-3 nodes whose label best matches the expanded tokens.
2. Run the appropriate traversal from each starting node.
3. Read the subgraph - node labels, edge relations, confidence tags, source locations.
4. Answer using **only** what the graph contains. Quote `source_location` when citing a specific fact.
5. If the graph lacks enough information, say so - do not hallucinate edges.

```bash
$(cat graphify-out/.graphify_python) -c "
import sys, json
from networkx.readwrite import json_graph
import networkx as nx
from pathlib import Path

data = json.loads(Path('graphify-out/graph.json').read_text(encoding='utf-8'))
G = json_graph.node_link_graph(data, edges='links')

question = sys.argv[1]
mode = sys.argv[2]  # 'bfs' or 'dfs'
terms = [t.lower() for t in question.split() if len(t) >= 3]  # match the vocab threshold; keeps api/jwt/ios (#1392)

# Find best-matching start nodes
scored = []
for nid, ndata in G.nodes(data=True):
    label = ndata.get('label', '').lower()
    score = sum(1 for t in terms if t in label)
    if score > 0:
        scored.append((score, nid))
scored.sort(reverse=True)
start_nodes = [nid for _, nid in scored[:3]]

if not start_nodes:
    print('No matching nodes found for query terms:', terms)
    sys.exit(0)

subgraph_nodes = set()
subgraph_edges = []

if mode == 'dfs':
    # DFS: follow one path as deep as possible before backtracking.
    # Depth-limited to 6 to avoid traversing the whole graph.
    visited = set()
    stack = [(n, 0) for n in reversed(start_nodes)]
    while stack:
        node, depth = stack.pop()
        if node in visited or depth > 6:
            continue
        visited.add(node)
        subgraph_nodes.add(node)
        for neighbor in G.neighbors(node):
            if neighbor not in visited:
                stack.append((neighbor, depth + 1))
                subgraph_edges.append((node, neighbor))
else:
    # BFS: explore all neighbors layer by layer up to depth 3.
    frontier = set(start_nodes)
    subgraph_nodes = set(start_nodes)
    for _ in range(3):
        next_frontier = set()
        for n in frontier:
            for neighbor in G.neighbors(n):
                if neighbor not in subgraph_nodes:
                    next_frontier.add(neighbor)
                    subgraph_edges.append((n, neighbor))
        subgraph_nodes.update(next_frontier)
        frontier = next_frontier

# Token-budget aware output: rank by relevance, cut at budget (~4 chars/token)
token_budget = int(sys.argv[3])  # default 2000
char_budget = token_budget * 4

# Score each node by term overlap for ranked output
def relevance(nid):
    label = G.nodes[nid].get('label', '').lower()
    return sum(1 for t in terms if t in label)

ranked_nodes = sorted(subgraph_nodes, key=relevance, reverse=True)

lines = [f'Traversal: {mode.upper()} | Start: {[G.nodes[n].get(\"label\",n) for n in start_nodes]} | {len(subgraph_nodes)} nodes']
for nid in ranked_nodes:
    d = G.nodes[nid]
    lines.append(f'  NODE {d.get(\"label\", nid)} [src={d.get(\"source_file\",\"\")} loc={d.get(\"source_location\",\"\")}]')
for u, v in subgraph_edges:
    if u in subgraph_nodes and v in subgraph_nodes:
        _raw = G[u][v]; d = next(iter(_raw.values()), {}) if isinstance(G, nx.MultiGraph) else _raw
        lines.append(f'  EDGE {G.nodes[u].get(\"label\",u)} --{d.get(\"relation\",\"\")} [{d.get(\"confidence\",\"\")}]--> {G.nodes[v].get(\"label\",v)}')

output = '\n'.join(lines)
if len(output) > char_budget:
    output = output[:char_budget] + f'\n... (truncated at ~{token_budget} token budget - use --budget N for more)'
print(output)
" "$(cat graphify-out/.graphify_question.txt)" MODE BUDGET
rc=$?; rm -f graphify-out/.graphify_question.txt; exit "$rc"
```

Write the **expanded** query string to `graphify-out/.graphify_question.txt` again first (the CLI block deleted it).
Replace `MODE` with `bfs` or `dfs`, and `BUDGET` with the token budget (default `2000`, or whatever `--budget N`
specifies). Then answer based on the subgraph output above, using only what the graph contains.

**Free text never goes on the command line.** Questions, answers and node labels come from the user, from you, or
from ingested documents. Inside double quotes `$(...)` and backticks run as commands, and a heredoc ends early at any
line equal to its delimiter, so none of them may carry this text. Write each value to its file under `graphify-out/`
with the Write tool, exactly as it should arrive, and let the command read the file: `"$(cat FILE)"` (the shell
never re-parses the output of a command substitution), `--answer-file` for answers, and the read loop below for node
labels, one label per line. The loop stops with an error on a label that starts with `-`, because `save-result`
would parse it as an option; for the same reason `save-result` gets its question as `--question="$(cat FILE)"`.
Every block deletes the files it read and exits with the graphify command's status, so write the files again
before the next block.

After writing the answer, save it back into the graph so it improves future queries. Include the expanded tokens inside the answer text (e.g. `"Expanded from original query via vocab: [tokens]. Then traversed..."`) so the next `--update` extracts the expansion history as a graph node:

```bash
set --
while IFS= read -r node || [ -n "$node" ]; do
    case $node in
        -*) printf 'graphify: refusing a node label that starts with "-": %s\n' "$node" >&2; exit 1 ;;
    esac
    [ -n "$node" ] && set -- "$@" "$node"
done < graphify-out/.graphify_nodes.txt
$(cat graphify-out/.graphify_python) -m graphify save-result --question="$(cat graphify-out/.graphify_question.txt)" \
    --answer-file graphify-out/.graphify_answer.txt --type query --nodes "$@"
rc=$?
rm -f graphify-out/.graphify_question.txt graphify-out/.graphify_answer.txt graphify-out/.graphify_nodes.txt
exit "$rc"
```

Before running it, write three files with the Write tool: `graphify-out/.graphify_question.txt` with the user's
verbatim question, `graphify-out/.graphify_answer.txt` with your full answer text (containing the expanded-token
trace), and `graphify-out/.graphify_nodes.txt` with the node labels you cited, one per line. This closes the feedback
loop: the next `--update` will extract this Q&A as a node in the graph.

**Work memory (self-improving loop).** Add an `--outcome` so future sessions learn from this one — add
`--outcome useful|dead_end|corrected` to the `save-result` command before `--nodes`. When correcting, also write the
right answer to `graphify-out/.graphify_correction.txt` with the Write tool, add
`--correction="$(cat graphify-out/.graphify_correction.txt)"` before `--nodes`, and add that file to the `rm -f` line:

- `useful` — the cited nodes answered the question well (they become *preferred sources*).
- `dead_end` — the question/path led nowhere; don't re-derive it next time.
- `corrected` — the saved answer was wrong; `--correction` records what was right.

At the **start** of graph work, refresh and read the lessons: run
`$(cat graphify-out/.graphify_python) -m graphify reflect --if-stale` (cheap, deterministic, no LLM; `--if-stale`
makes it a no-op when `LESSONS.md` is already newer than every input, e.g. when the git hook just refreshed it), then
read `graphify-out/reflections/LESSONS.md`. It lists **preferred sources** (start there), **known dead ends** (skip
them), and prior **corrections**. Running `reflect` yourself keeps the lessons current even without the git hook
installed; if the post-commit hook *is* installed, `--if-stale` means your session-start run costs almost nothing.

---

## For /graphify path

Find the shortest path between two named concepts in the graph. Write the user's two concept names to
`graphify-out/.graphify_node_a.txt` and `graphify-out/.graphify_node_b.txt` with the Write tool, then prefer the CLI
when installed:

```bash
$(cat graphify-out/.graphify_python) -m graphify path \
    "$(cat graphify-out/.graphify_node_a.txt)" "$(cat graphify-out/.graphify_node_b.txt)"
rc=$?; rm -f graphify-out/.graphify_node_a.txt graphify-out/.graphify_node_b.txt; exit "$rc"
```

If the CLI is unavailable, run it inline:

```bash
$(cat graphify-out/.graphify_python) -c "
import json, sys
import networkx as nx
from networkx.readwrite import json_graph
from pathlib import Path

data = json.loads(Path('graphify-out/graph.json').read_text(encoding='utf-8'))
G = json_graph.node_link_graph(data, edges='links')

a_term = sys.argv[1]
b_term = sys.argv[2]

def find_node(term):
    term = term.lower()
    scored = sorted(
        [(sum(1 for w in term.split() if w in G.nodes[n].get('label','').lower()), n)
         for n in G.nodes()],
        reverse=True
    )
    return scored[0][1] if scored and scored[0][0] > 0 else None

src = find_node(a_term)
tgt = find_node(b_term)

if not src or not tgt:
    print(f'Could not find nodes matching: {a_term!r} or {b_term!r}')
    sys.exit(0)

try:
    path = nx.shortest_path(G, src, tgt)
    print(f'Shortest path ({len(path)-1} hops):')
    for i, nid in enumerate(path):
        label = G.nodes[nid].get('label', nid)
        if i < len(path) - 1:
            _raw = G[nid][path[i+1]]; edge = next(iter(_raw.values()), {}) if isinstance(G, nx.MultiGraph) else _raw
            rel = edge.get('relation', '')
            conf = edge.get('confidence', '')
            print(f'  {label} --{rel}--> [{conf}]')
        else:
            print(f'  {label}')
except nx.NetworkXNoPath:
    print(f'No path found between {a_term!r} and {b_term!r}')
except nx.NodeNotFound as e:
    print(f'Node not found: {e}')
" "$(cat graphify-out/.graphify_node_a.txt)" "$(cat graphify-out/.graphify_node_b.txt)"
rc=$?; rm -f graphify-out/.graphify_node_a.txt graphify-out/.graphify_node_b.txt; exit "$rc"
```

Write the two concept names to `graphify-out/.graphify_node_a.txt` and `graphify-out/.graphify_node_b.txt` again
first (the CLI block deleted them). Then explain the path in plain language - what each hop means, why it's
significant.

After writing the explanation, save it back. Write `Path from <first concept> to <second concept>` to
`graphify-out/.graphify_question.txt`, the explanation to `graphify-out/.graphify_answer.txt`, and the two concept
names, one per line, to `graphify-out/.graphify_nodes.txt` with the Write tool, then run:

```bash
set --
while IFS= read -r node || [ -n "$node" ]; do
    case $node in
        -*) printf 'graphify: refusing a node label that starts with "-": %s\n' "$node" >&2; exit 1 ;;
    esac
    [ -n "$node" ] && set -- "$@" "$node"
done < graphify-out/.graphify_nodes.txt
$(cat graphify-out/.graphify_python) -m graphify save-result --question="$(cat graphify-out/.graphify_question.txt)" \
    --answer-file graphify-out/.graphify_answer.txt --type path_query --nodes "$@"
rc=$?
rm -f graphify-out/.graphify_question.txt graphify-out/.graphify_answer.txt graphify-out/.graphify_nodes.txt
exit "$rc"
```

---

## For /graphify explain

Give a plain-language explanation of a single node - everything connected to it. Write the concept the user asked
about to `graphify-out/.graphify_node.txt` with the Write tool, then prefer the CLI when installed:

```bash
$(cat graphify-out/.graphify_python) -m graphify explain "$(cat graphify-out/.graphify_node.txt)"
rc=$?; rm -f graphify-out/.graphify_node.txt; exit "$rc"
```

If the CLI is unavailable, run it inline:

```bash
$(cat graphify-out/.graphify_python) -c "
import json, sys
import networkx as nx
from networkx.readwrite import json_graph
from pathlib import Path

data = json.loads(Path('graphify-out/graph.json').read_text(encoding='utf-8'))
G = json_graph.node_link_graph(data, edges='links')

term = sys.argv[1]
term_lower = term.lower()

# Find best matching node
scored = sorted(
    [(sum(1 for w in term_lower.split() if w in G.nodes[n].get('label','').lower()), n)
     for n in G.nodes()],
    reverse=True
)
if not scored or scored[0][0] == 0:
    print(f'No node matching {term!r}')
    sys.exit(0)

nid = scored[0][1]
data_n = G.nodes[nid]
print(f'NODE: {data_n.get(\"label\", nid)}')
print(f'  source: {data_n.get(\"source_file\",\"unknown\")}')
print(f'  type: {data_n.get(\"file_type\",\"unknown\")}')
print(f'  degree: {G.degree(nid)}')
print()
print('CONNECTIONS:')
for neighbor in G.neighbors(nid):
    _raw = G[nid][neighbor]; edge = next(iter(_raw.values()), {}) if isinstance(G, nx.MultiGraph) else _raw
    nlabel = G.nodes[neighbor].get('label', neighbor)
    rel = edge.get('relation', '')
    conf = edge.get('confidence', '')
    src_file = G.nodes[neighbor].get('source_file', '')
    print(f'  --{rel}--> {nlabel} [{conf}] ({src_file})')
" "$(cat graphify-out/.graphify_node.txt)"
rc=$?; rm -f graphify-out/.graphify_node.txt; exit "$rc"
```

Write the concept to `graphify-out/.graphify_node.txt` again first (the CLI block deleted it). Then write a 3-5
sentence explanation of what this node is, what it connects to, and why those connections are significant. Use the
source locations as citations.

After writing the explanation, save it back. Write `Explain <concept>` to `graphify-out/.graphify_question.txt`, the
explanation to `graphify-out/.graphify_answer.txt`, and the concept to `graphify-out/.graphify_nodes.txt` with the
Write tool, then run:

```bash
set --
while IFS= read -r node || [ -n "$node" ]; do
    case $node in
        -*) printf 'graphify: refusing a node label that starts with "-": %s\n' "$node" >&2; exit 1 ;;
    esac
    [ -n "$node" ] && set -- "$@" "$node"
done < graphify-out/.graphify_nodes.txt
$(cat graphify-out/.graphify_python) -m graphify save-result --question="$(cat graphify-out/.graphify_question.txt)" \
    --answer-file graphify-out/.graphify_answer.txt --type explain --nodes "$@"
rc=$?
rm -f graphify-out/.graphify_question.txt graphify-out/.graphify_answer.txt graphify-out/.graphify_nodes.txt
exit "$rc"
```
