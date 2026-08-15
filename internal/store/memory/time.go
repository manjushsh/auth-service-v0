package memory

import (
	"strconv"
	"time"
)

func formatUnix(t time.Time) string { return strconv.FormatInt(t.Unix(), 10) }

func parseUnix(s string) (time.Time, error) {
	secs, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(secs, 0).UTC(), nil
}
