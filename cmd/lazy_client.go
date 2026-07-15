package cmd

import (
	"context"
	"sync"

	"github.com/ivuorinen/f2b/fail2ban"
)

// lazyClient defers construction of the real fail2ban client until the first
// time a client operation is actually invoked. This means:
//   - Commands that never touch the client (help, version, completion, service)
//     work without fail2ban installed or sudo privileges.
//   - The client is built from the global cfg AFTER cobra has parsed flags, so
//     --log-dir/--filter-dir take effect (they were previously read in main()
//     before flag parsing and silently ignored).
//
// It implements fail2ban.Client by resolving the real client on demand and
// delegating; a construction failure surfaces as the operation's error.
type lazyClient struct {
	once   sync.Once
	client fail2ban.Client
	err    error
}

// NewLazyClient returns a fail2ban.Client that constructs the real client on
// first use, reading cfg.LogDir/cfg.FilterDir at that point.
func NewLazyClient() fail2ban.Client {
	return &lazyClient{}
}

func (l *lazyClient) resolve() (fail2ban.Client, error) {
	l.once.Do(func() {
		l.client, l.err = fail2ban.NewClient(cfg.LogDir, cfg.FilterDir)
	})
	return l.client, l.err
}

func (l *lazyClient) ListJails() ([]string, error) {
	c, err := l.resolve()
	if err != nil {
		return nil, err
	}
	return c.ListJails()
}

func (l *lazyClient) StatusAll() (string, error) {
	c, err := l.resolve()
	if err != nil {
		return "", err
	}
	return c.StatusAll()
}

func (l *lazyClient) StatusJail(jail string) (string, error) {
	c, err := l.resolve()
	if err != nil {
		return "", err
	}
	return c.StatusJail(jail)
}

func (l *lazyClient) BanIP(ip, jail string) (int, error) {
	c, err := l.resolve()
	if err != nil {
		return 0, err
	}
	return c.BanIP(ip, jail)
}

func (l *lazyClient) UnbanIP(ip, jail string) (int, error) {
	c, err := l.resolve()
	if err != nil {
		return 0, err
	}
	return c.UnbanIP(ip, jail)
}

func (l *lazyClient) BannedIn(ip string) ([]string, error) {
	c, err := l.resolve()
	if err != nil {
		return nil, err
	}
	return c.BannedIn(ip)
}

func (l *lazyClient) GetBanRecords(jails []string) ([]fail2ban.BanRecord, error) {
	c, err := l.resolve()
	if err != nil {
		return nil, err
	}
	return c.GetBanRecords(jails)
}

func (l *lazyClient) GetLogLines(jail, ip string) ([]string, error) {
	c, err := l.resolve()
	if err != nil {
		return nil, err
	}
	return c.GetLogLines(jail, ip)
}

func (l *lazyClient) ListFilters() ([]string, error) {
	c, err := l.resolve()
	if err != nil {
		return nil, err
	}
	return c.ListFilters()
}

func (l *lazyClient) TestFilter(filter string) (string, error) {
	c, err := l.resolve()
	if err != nil {
		return "", err
	}
	return c.TestFilter(filter)
}

func (l *lazyClient) ListJailsWithContext(ctx context.Context) ([]string, error) {
	c, err := l.resolve()
	if err != nil {
		return nil, err
	}
	return c.ListJailsWithContext(ctx)
}

func (l *lazyClient) StatusAllWithContext(ctx context.Context) (string, error) {
	c, err := l.resolve()
	if err != nil {
		return "", err
	}
	return c.StatusAllWithContext(ctx)
}

func (l *lazyClient) StatusJailWithContext(ctx context.Context, jail string) (string, error) {
	c, err := l.resolve()
	if err != nil {
		return "", err
	}
	return c.StatusJailWithContext(ctx, jail)
}

func (l *lazyClient) BanIPWithContext(ctx context.Context, ip, jail string) (int, error) {
	c, err := l.resolve()
	if err != nil {
		return 0, err
	}
	return c.BanIPWithContext(ctx, ip, jail)
}

func (l *lazyClient) UnbanIPWithContext(ctx context.Context, ip, jail string) (int, error) {
	c, err := l.resolve()
	if err != nil {
		return 0, err
	}
	return c.UnbanIPWithContext(ctx, ip, jail)
}

func (l *lazyClient) BannedInWithContext(ctx context.Context, ip string) ([]string, error) {
	c, err := l.resolve()
	if err != nil {
		return nil, err
	}
	return c.BannedInWithContext(ctx, ip)
}

func (l *lazyClient) GetBanRecordsWithContext(ctx context.Context, jails []string) ([]fail2ban.BanRecord, error) {
	c, err := l.resolve()
	if err != nil {
		return nil, err
	}
	return c.GetBanRecordsWithContext(ctx, jails)
}

func (l *lazyClient) GetLogLinesWithContext(ctx context.Context, jail, ip string) ([]string, error) {
	c, err := l.resolve()
	if err != nil {
		return nil, err
	}
	return c.GetLogLinesWithContext(ctx, jail, ip)
}

func (l *lazyClient) ListFiltersWithContext(ctx context.Context) ([]string, error) {
	c, err := l.resolve()
	if err != nil {
		return nil, err
	}
	return c.ListFiltersWithContext(ctx)
}

func (l *lazyClient) TestFilterWithContext(ctx context.Context, filter string) (string, error) {
	c, err := l.resolve()
	if err != nil {
		return "", err
	}
	return c.TestFilterWithContext(ctx, filter)
}

// GetLogLinesWithLimitContext exposes the read-time line-limit capability
// through the lazy wrapper. Without this the logLinesLimiter assertion in the
// logs/logs-watch commands never matched in production (the client is always
// a lazyClient), so any -n above the fail2ban layer's default cap silently
// truncated to that cap.
func (l *lazyClient) GetLogLinesWithLimitContext(
	ctx context.Context, jail, ip string, maxLines int,
) ([]string, error) {
	c, err := l.resolve()
	if err != nil {
		return nil, err
	}
	if lc, ok := c.(logLinesLimiter); ok {
		return lc.GetLogLinesWithLimitContext(ctx, jail, ip, maxLines)
	}
	lines, err := c.GetLogLinesWithContext(ctx, jail, ip)
	if err != nil {
		return nil, err
	}
	if maxLines > 0 && len(lines) > maxLines {
		lines = lines[len(lines)-maxLines:]
	}
	return lines, nil
}

// Ensure lazyClient satisfies the Client interface and the optional
// line-limit capability.
var (
	_ fail2ban.Client = (*lazyClient)(nil)
	_ logLinesLimiter = (*lazyClient)(nil)
)
