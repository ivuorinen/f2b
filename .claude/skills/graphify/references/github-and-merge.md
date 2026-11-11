# graphify reference: GitHub clone and cross-repo merge

Load this when the user passed one or more `https://github.com/...` URLs, or named several local subfolders to merge into one graph.

### Step 0 - Clone GitHub repo(s) (only if a GitHub URL was given)

Run the SKILL.md Step 1 interpreter block first, so `graphify-out/.graphify_python` exists. URLs, branch names and
the paths below come from the user or from a cloned repository, so they reach graphify only through files you write
with the Write tool, never typed into a command.

**Single repo:** write the URL to `graphify-out/.graphify_clone_url.txt` (and a `--branch` name, if given, to
`graphify-out/.graphify_clone_branch.txt`), then run:
```bash
set -- "$(cat graphify-out/.graphify_clone_url.txt)"
if [ -f graphify-out/.graphify_clone_branch.txt ]; then
    set -- "$@" --branch "$(cat graphify-out/.graphify_clone_branch.txt)"
fi
$(cat graphify-out/.graphify_python) -m graphify clone "$@"   # prints the local path
rc=$?; rm -f graphify-out/.graphify_clone_url.txt graphify-out/.graphify_clone_branch.txt; exit "$rc"
```
Use the printed path as the target for all subsequent steps: it is the path you write to
`graphify-out/.graphify_input_path.txt` in Step 1.

**Multiple repos (cross-repo graph):** clone each URL with the single-repo block (each prints
`~/.graphify/repos/<owner>/<repo>` as an absolute path) and run /graphify on each printed path to produce its
`graph.json`. Then write those `graph.json` paths, absolute and one per line, to
`graphify-out/.graphify_merge_inputs.txt` and merge:
```bash
set --
while IFS= read -r p || [ -n "$p" ]; do
    case $p in
        -*) printf 'graphify: refusing a path that starts with "-": %s\n' "$p" >&2; exit 1 ;;
    esac
    [ -n "$p" ] && set -- "$@" "$p"
done < graphify-out/.graphify_merge_inputs.txt
$(cat graphify-out/.graphify_python) -m graphify merge-graphs "$@" --out graphify-out/cross-repo-graph.json
rc=$?; rm -f graphify-out/.graphify_merge_inputs.txt; exit "$rc"
```

Graphify clones into `~/.graphify/repos/<owner>/<repo>` and reuses existing clones on repeat runs. Each node in the merged graph carries a `repo` attribute so you can filter by origin.

**Multiple local subfolders (monorepo or multi-service layout):**

The skill pipeline writes all intermediate and final outputs to `graphify-out/` in the current working directory. Running the skill on each subfolder separately will clobber the same output dir. Instead, use the CLI directly for each subfolder — it places `graphify-out/` *inside* the scanned path:

For each subfolder (e.g. `./core/`, `./service/`, `./platform/`), write its path, starting with `./` so a name that
begins with `-` is not read as an option, to `graphify-out/.graphify_subfolder.txt` with the Write tool and run:

```bash
# → <subfolder>/graphify-out/graph.json
# --code-only keeps every file on this machine. Without it, `graphify extract`
# sends docs, papers and images to whichever LLM provider has a key in the
# environment (Gemini first), even one exported for another tool. Extract
# those with /graphify in the assistant instead.
$(cat graphify-out/.graphify_python) -m graphify extract "$(cat graphify-out/.graphify_subfolder.txt)" --code-only
rc=$?; rm -f graphify-out/.graphify_subfolder.txt; exit "$rc"
```

Then merge at the project root: write the subfolders' `graph.json` paths (e.g. `./core/graphify-out/graph.json`),
one per line, to `graphify-out/.graphify_merge_inputs.txt`, and run the merge block above with
`--out graphify-out/graph.json` in place of `--out graphify-out/cross-repo-graph.json`.

Once `graphify-out/graph.json` exists, the fast path above takes over: any codebase question goes through the query
flow directly on the merged graph — no re-extraction, no size gate.
