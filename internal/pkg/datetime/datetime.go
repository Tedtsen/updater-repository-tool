package datetime

import (
	"time"
)

func ExpireIn(days int) time.Time {
	return time.Now().AddDate(0, 0, days).UTC()
}
