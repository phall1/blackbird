package cli

import (
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/phall1/blackbird/internal/cli/render"
)

func orAbsent(value string) string {
	if value == "" {
		return render.Absent
	}
	return value
}

func yesNo(value bool) string {
	if value {
		return "yes"
	}
	return "no"
}

func boolRole(value bool) render.Role {
	if value {
		return render.RoleOK
	}
	return render.RoleWarn
}

func itoa(value int) string { return strconv.Itoa(value) }

func utoa(value uint64) string { return strconv.FormatUint(value, 10) }

func hasPrefix(value, prefix string) bool { return strings.HasPrefix(value, prefix) }

// instant renders an RFC 3339 timestamp from the admin surface relative to now,
// falling back to the raw string when the daemon reports a form we do not know.
func instant(value string, now time.Time) string {
	if value == "" {
		return render.Absent
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return value
	}
	return render.RelativeTime(parsed, now)
}

func countdown(milliseconds int64) string {
	if milliseconds == 0 {
		return render.Absent
	}
	if milliseconds < 0 {
		return "-" + render.Duration(time.Duration(-milliseconds)*time.Millisecond)
	}
	return render.Duration(time.Duration(milliseconds) * time.Millisecond)
}

func selectorPaths(selectors []Selector) string {
	if len(selectors) == 0 {
		return render.Absent
	}
	paths := make([]string, 0, len(selectors))
	for _, selector := range selectors {
		paths = append(paths, selector.Path)
	}
	return strings.Join(paths, " ")
}

// projectKeyOrWorkingDirectory resolves the project key an agent registers
// under, which is the absolute path of the workspace it is working in.
func projectKeyOrWorkingDirectory(configured string) (string, error) {
	if configured != "" {
		return configured, nil
	}
	working, err := os.Getwd()
	if err != nil {
		return "", withRemedy(usageFault("resolve the current directory: %v", err), "pass --project=PATH")
	}
	return working, nil
}

// limitOf rejects a page size that asks for nothing. Zero and negatives reach
// the daemon as "unset" and select its default of 50, so a user who typed
// --limit=0 would be shown 50 rows and read them as the whole answer.
func limitOf(flag string, value int) (int, error) {
	if value < 1 {
		return 0, withRemedy(usageFault("%s must be at least 1, got %d", flag, value),
			"drop "+flag+" to accept the default page size")
	}
	return value, nil
}

// drawTruncation marks a page the daemon could not fit under its limit. Without
// it a partial list is indistinguishable from a complete one.
func drawTruncation(doc *render.Document, truncated bool, shown int) {
	if !truncated {
		return
	}
	doc.Linef(render.RoleWarn, "showing %d rows; more matched than fit: raise --limit to see the rest", shown)
}
