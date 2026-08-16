package cli

import "testing"

// TestServiceFactsKeepValuesThatContainSpaces is the regression for splitting
// the installer's status line on whitespace: a home directory with a space was
// truncated at the space, and the systemd detail in "stopped (inactive)" was
// dropped entirely.
func TestServiceFactsKeepValuesThatContainSpaces(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		line string
		want map[string]string
	}{
		{
			name: "darwin detail",
			line: "daemon=running (0.4.0) installed=true path=/service definition=stale " +
				"updater=scheduled installed=true paths=/updater interval=6h0m0s",
			want: map[string]string{
				"daemon": "running (0.4.0)", "installed": "true", "path": "/service",
				"definition": "stale", "updater": "scheduled", "updater_installed": "true",
				"paths": "/updater", "interval": "6h0m0s",
			},
		},
		{
			name: "linux detail",
			line: "daemon=stopped (inactive) installed=true path=/service definition=current " +
				"updater=stopped (inactive) installed=false paths= interval=6h0m0s",
			want: map[string]string{
				"daemon": "stopped (inactive)", "installed": "true", "path": "/service",
				"definition": "current", "updater": "stopped (inactive)", "updater_installed": "false",
				"paths": "", "interval": "6h0m0s",
			},
		},
		{
			name: "path with a space",
			line: "daemon=not-installed installed=false " +
				"path=/Users/pat hall/Library/LaunchAgents/com.phall1.blackbird.plist " +
				"definition=absent updater=stopped installed=false " +
				"paths=/Users/pat hall/Library/LaunchAgents/com.phall1.blackbird-update.plist interval=6h0m0s",
			want: map[string]string{
				"daemon": "not-installed", "installed": "false",
				"path":       "/Users/pat hall/Library/LaunchAgents/com.phall1.blackbird.plist",
				"definition": "absent", "updater": "stopped", "updater_installed": "false",
				"paths":    "/Users/pat hall/Library/LaunchAgents/com.phall1.blackbird-update.plist",
				"interval": "6h0m0s",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			facts := serviceFacts(test.line)
			if len(facts) != len(test.want) {
				t.Fatalf("facts = %#v, want %#v", facts, test.want)
			}
			for key, want := range test.want {
				if facts[key] != want {
					t.Fatalf("facts[%q] = %q, want %q", key, facts[key], want)
				}
			}
		})
	}
}

func TestServiceFactsIgnoresTokensThatAreNotPairs(t *testing.T) {
	t.Parallel()

	facts := serviceFacts("waiting for launchd")
	if len(facts) != 0 {
		t.Fatalf("facts = %#v, want none", facts)
	}
	if facts := serviceFacts(""); len(facts) != 0 {
		t.Fatalf("facts = %#v, want none", facts)
	}
}
