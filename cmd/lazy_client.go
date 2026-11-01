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

// resolve builds the real client on first use under ctx, the context of the
// operation that triggered it. Construction runs fail2ban-client -V, ping and
// status; building under context.Background() let those ignore the command's
// timeout and Ctrl-C. A CLI process runs one command, so the first caller's
// context is the command's context.
func (l *lazyClient) resolve(ctx context.Context) (fail2ban.Client, error) {
	l.once.Do(func() {
		l.client, l.err = fail2ban.NewClientWithContext(ctx, cfg.LogDir, cfg.FilterDir)
	})
	return l.client, l.err
}

func (l *lazyClient) ListJailsWithContext(ctx context.Context) ([]string, error) {
	c, err := l.resolve(ctx)
	if err != nil {
		return nil, err
	}
	return c.ListJailsWithContext(ctx)
}

func (l *lazyClient) StatusAllWithContext(ctx context.Context) (string, error) {
	c, err := l.resolve(ctx)
	if err != nil {
		return "", err
	}
	return c.StatusAllWithContext(ctx)
}

func (l *lazyClient) StatusJailWithContext(ctx context.Context, jail string) (string, error) {
	c, err := l.resolve(ctx)
	if err != nil {
		return "", err
	}
	return c.StatusJailWithContext(ctx, jail)
}

func (l *lazyClient) BanIPWithContext(ctx context.Context, ip, jail string) (int, error) {
	c, err := l.resolve(ctx)
	if err != nil {
		return 0, err
	}
	return c.BanIPWithContext(ctx, ip, jail)
}

func (l *lazyClient) UnbanIPWithContext(ctx context.Context, ip, jail string) (int, error) {
	c, err := l.resolve(ctx)
	if err != nil {
		return 0, err
	}
	return c.UnbanIPWithContext(ctx, ip, jail)
}

func (l *lazyClient) BannedInWithContext(ctx context.Context, ip string) ([]string, error) {
	c, err := l.resolve(ctx)
	if err != nil {
		return nil, err
	}
	return c.BannedInWithContext(ctx, ip)
}

func (l *lazyClient) GetBanRecordsWithContext(ctx context.Context, jails []string) ([]fail2ban.BanRecord, error) {
	c, err := l.resolve(ctx)
	if err != nil {
		return nil, err
	}
	return c.GetBanRecordsWithContext(ctx, jails)
}

func (l *lazyClient) GetLogLinesWithContext(ctx context.Context, jail, ip string) ([]string, error) {
	c, err := l.resolve(ctx)
	if err != nil {
		return nil, err
	}
	return c.GetLogLinesWithContext(ctx, jail, ip)
}

func (l *lazyClient) GetLogLinesWithLimitContext(
	ctx context.Context, jail, ip string, maxLines int,
) ([]string, error) {
	c, err := l.resolve(ctx)
	if err != nil {
		return nil, err
	}
	return c.GetLogLinesWithLimitContext(ctx, jail, ip, maxLines)
}

func (l *lazyClient) ListFiltersWithContext(ctx context.Context) ([]string, error) {
	c, err := l.resolve(ctx)
	if err != nil {
		return nil, err
	}
	return c.ListFiltersWithContext(ctx)
}

func (l *lazyClient) TestFilterWithContext(ctx context.Context, filter string) (string, error) {
	c, err := l.resolve(ctx)
	if err != nil {
		return "", err
	}
	return c.TestFilterWithContext(ctx, filter)
}

// Ensure lazyClient satisfies the Client interface.
var _ fail2ban.Client = (*lazyClient)(nil)
