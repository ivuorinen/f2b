package fail2ban

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ivuorinen/f2b/constants"
)

// Sentinel errors for parser
var (
	ErrEmptyLine      = errors.New("empty line")
	ErrInvalidBanTime = errors.New("invalid ban time")
)

// parseBanTime parses a fail2ban-client timestamp. They carry no zone, and
// time.Parse would read them as UTC, skewing "remaining" by the host's UTC
// offset and clamping fresh bans to 0 east of UTC.
func parseBanTime(value string) (time.Time, error) {
	return time.ParseInLocation(constants.TimeFormat, value, time.Local)
}

// parseBanRecordLine parses a single ban record line.
func parseBanRecordLine(line, jail string) (*BanRecord, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil, ErrEmptyLine
	}
	fields := strings.Fields(line)

	// Validate jail name for path traversal
	if jail == "" || strings.ContainsAny(jail, "/\\") || strings.Contains(jail, "..") {
		return nil, fmt.Errorf("invalid jail name: contains unsafe characters")
	}

	// fail2ban can also ban an arbitrary ID captured from a log line; those
	// are refused so that log-derived text does not reach the terminal.
	if ValidateBanTarget(fields[0]) != nil {
		return nil, fmt.Errorf(constants.ErrInvalidIPAddress, fields[0])
	}

	record := &BanRecord{Jail: jail, IP: fields[0]}

	// Full format carries ban and unban timestamps (>= 6 fields).
	// The 8-field upstream variant "IP date time + SECS = date time" and the
	// 7-field "IP date time + date time remaining" both have ban time at
	// fields[1..2]; parseFullFormat locates the unban time for each.
	if len(fields) >= 6 {
		err := parseFullFormat(fields, record)
		if err == nil {
			return record, nil
		}
		if len(fields) >= 8 {
			// 8+ fields is the well-known upstream layout: unparseable
			// timestamps there mean a genuinely malformed record.
			return nil, err
		}
		// A 6/7-field line whose fields aren't timestamps is an exotic
		// variant, not garbage: fall through to the simple-format record
		// instead of dropping the line.
	}

	// Fallback for simple format
	record.BannedAt = time.Now()
	record.Remaining = constants.UnknownValue
	return record, nil
}

// parseFullFormat handles the full ban-record format (ban + unban timestamps),
// filling record's BannedAt and Remaining. Ban date/time is always
// fields[1]/fields[2]. The unban timestamp position depends on the layout
// emitted by fail2ban-client:
//   - 8-field "IP date time + SECS = date time": "=" at index 5, unban at 6/7
//   - 6/7-field "IP date time + date time [remaining]": unban at 4/5
func parseFullFormat(fields []string, record *BanRecord) error {
	bannedStr := fields[1] + " " + fields[2]
	unbanStr := fields[4] + " " + fields[5]
	if len(fields) >= 8 && fields[5] == "=" {
		unbanStr = fields[6] + " " + fields[7]
	}

	// Parse ban time
	tBan, err := parseBanTime(bannedStr)
	if err != nil {
		getLogger().WithFields(Fields{
			"jail":      record.Jail,
			"ip":        record.IP,
			"bannedStr": bannedStr,
		}).Warnf("Failed to parse ban time: %v", err)
		return ErrInvalidBanTime
	}

	// Parse unban time with fallback
	tUnban, err := parseBanTime(unbanStr)
	if err != nil {
		getLogger().WithFields(Fields{
			"jail":     record.Jail,
			"ip":       record.IP,
			"unbanStr": unbanStr,
		}).Warnf("Failed to parse unban time: %v", err)
		tUnban = time.Now().Add(constants.DefaultBanDuration) // 24h fallback
	}

	record.BannedAt = tBan
	// fail2ban clamps a permanent ban's end to the year 9999, which would
	// otherwise print as a remaining time of millions of days.
	if len(fields) >= 8 && fields[4] == constants.PermanentBanTime {
		record.Remaining = constants.PermanentBan
		return nil
	}
	record.Remaining = formatDuration(max(tUnban.Unix()-time.Now().Unix(), 0))
	return nil
}

// hasBanListLayout reports whether line has fail2ban's ban list layout,
// "ID \tDATE TIME + SECS = DATE TIME". It reads from the end because an ID can
// hold spaces. The layout separates a ban that could not be read from stderr
// noise, such as a config warning, which arrives in the same output.
func hasBanListLayout(line string) bool {
	fields := strings.Fields(line)
	n := len(fields)
	return n >= 8 && fields[n-5] == "+" && fields[n-3] == "="
}

// ParseBanRecords parses `fail2ban-client get <jail> banip --with-time`
// output. Lines that fail to parse are
// skipped and counted in a warning, so the bans that can be read are still
// listed. When fail2ban lists bans and none can be read, it returns an error:
// an empty result would report a jail with active bans as having none.
func ParseBanRecords(output, jail string) ([]BanRecord, error) {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	records := make([]BanRecord, 0, len(lines))
	skipped, unreadable := 0, 0

	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		record, err := parseBanRecordLine(line, jail)
		if err != nil {
			skipped++
			if hasBanListLayout(line) {
				unreadable++
			}
			continue
		}
		records = append(records, *record)
	}

	if len(records) == 0 && unreadable > 0 {
		return nil, fmt.Errorf("none of the %d ban records could be read", unreadable)
	}
	if skipped > 0 {
		getLogger().WithField("jail", jail).WithField("skipped", skipped).
			Warn("Skipped unparseable ban record lines")
	}
	return records, nil
}

// formatDuration formats seconds as DD:HH:MM:SS, the shape fail2ban users expect.
func formatDuration(sec int64) string {
	days := sec / constants.SecondsPerDay
	h := (sec % constants.SecondsPerDay) / constants.SecondsPerHour
	m := (sec % constants.SecondsPerHour) / constants.SecondsPerMinute
	s := sec % constants.SecondsPerMinute
	return fmt.Sprintf("%02d:%02d:%02d:%02d", days, h, m, s)
}
