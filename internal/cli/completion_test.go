package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func generatedCompletion(t *testing.T, shell string) string {
	t.Helper()
	result := runCLI(t, dependencies(t), []string{"completion", shell})
	if result.code != ExitOK {
		t.Fatalf("completion %s = %d; stderr=%q", shell, result.code, result.stderr)
	}
	return result.stdout
}

// TestBashCompletionUsesNoBash4Builtins is the regression for emitting mapfile:
// macOS ships /bin/bash 3.2.57, where a bash 4 builtin turns every Tab press
// into "command not found" and completes nothing.
func TestBashCompletionUsesNoBash4Builtins(t *testing.T) {
	t.Parallel()

	script := generatedCompletion(t, "bash")
	for _, forbidden := range []string{"mapfile", "readarray", "declare -A", "local -A", ";;&", "${!"} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("bash script uses %q, which bash 3.2 does not have:\n%s", forbidden, script)
		}
	}
	if !strings.Contains(script, "compgen -W") || !strings.Contains(script, "complete -F _blackbird blackbird") {
		t.Fatalf("bash script does not register a completion:\n%s", script)
	}
}

// completeUnderBash sources the generated script in the shell the primary
// platform actually ships and returns what a Tab press on words would offer.
func completeUnderBash(t *testing.T, words ...string) string {
	t.Helper()

	shell := "/bin/bash"
	if _, err := os.Stat(shell); err != nil {
		resolved, lookErr := exec.LookPath("bash")
		if lookErr != nil {
			t.Skip("no bash on this machine")
		}
		shell = resolved
	}
	directory := t.TempDir()
	scriptPath := filepath.Join(directory, "blackbird.bash")
	if err := os.WriteFile(scriptPath, []byte(generatedCompletion(t, "bash")), 0o600); err != nil {
		t.Fatal(err)
	}
	driverPath := filepath.Join(directory, "drive.bash")
	driver := "source " + scriptPath + "\n" +
		"COMP_WORDS=(" + strings.Join(words, " ") + ")\n" +
		"COMP_CWORD=" + strconv.Itoa(len(words)-1) + "\n" +
		"_blackbird\n" +
		`printf '%s\n' "${COMPREPLY[*]}"` + "\n"
	if err := os.WriteFile(driverPath, []byte(driver), 0o600); err != nil {
		t.Fatal(err)
	}

	output, err := exec.Command(shell, driverPath).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s = %v; output=%s", shell, driverPath, err, output)
	}
	return strings.TrimSpace(string(output))
}

// TestBashCompletionCompletesUnderTheSystemBash runs the generated script in the
// shell the primary platform actually uses and completes a prefix.
func TestBashCompletionCompletesUnderTheSystemBash(t *testing.T) {
	t.Parallel()

	if got := completeUnderBash(t, "blackbird", "in"); got != "inbox install" {
		t.Fatalf("completions for \"blackbird in\" = %q, want \"inbox install\"", got)
	}
}

// TestBashCompletionOffersFlagsWhereTheGrammarAcceptsThem is the regression for
// three dead ends: a command with a default subcommand offered only that
// subcommand's name even though its flags parse without it, the globals parsed
// at every depth but were offered only at the root, and the path walk read a
// consumed flag value as a subcommand, which left every later word on a path no
// arm of the case statement matches.
func TestBashCompletionOffersFlagsWhereTheGrammarAcceptsThem(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		words []string
		want  string
	}{
		{
			name:  "default subcommand lends its flags",
			words: []string{"blackbird", "reservations", "--mo"},
			want:  "--mode",
		},
		{
			name:  "a global parses under a command, so it completes there",
			words: []string{"blackbird", "status", "--js"},
			want:  "--json",
		},
		{
			name:  "a leaf that declares no flag of its own still has the globals",
			words: []string{"blackbird", "projects", "list", "--v"},
			want:  "--verbose --version",
		},
		{
			name:  "a group node with only subcommands offers them and the globals",
			words: []string{"blackbird", "projects", "s"},
			want:  "show",
		},
		{
			name:  "the named subcommand keeps its own",
			words: []string{"blackbird", "reservations", "list", "--mo"},
			want:  "--mode",
		},
		{
			name:  "completion resumes after a consumed flag value",
			words: []string{"blackbird", "inbox", "--limit", "5", "--un"},
			want:  "--unacked --unread",
		},
		{
			name:  "a word-broken flag value is consumed too",
			words: []string{"blackbird", "inbox", "--limit", "=", "5", "--un"},
			want:  "--unacked --unread",
		},
		{
			name:  "a counter consumes nothing",
			words: []string{"blackbird", "-v", "stat"},
			want:  "status",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if got := completeUnderBash(t, test.words...); got != test.want {
				t.Fatalf("completions for %q = %q, want %q", strings.Join(test.words, " "), got, test.want)
			}
		})
	}
}

func TestZshAndFishCompletionsKeepTheirShellHeaders(t *testing.T) {
	t.Parallel()

	zsh := generatedCompletion(t, "zsh")
	if !strings.HasPrefix(zsh, "#compdef blackbird") || !strings.Contains(zsh, "compdef _blackbird blackbird") {
		t.Fatalf("zsh script = %q", zsh)
	}
	fish := generatedCompletion(t, "fish")
	if !strings.HasPrefix(fish, "complete -c blackbird -f") {
		t.Fatalf("fish script = %q", fish)
	}
	for _, script := range []string{zsh, fish} {
		if strings.Contains(script, "COMPREPLY") {
			t.Fatalf("script leaked bash internals: %q", script)
		}
	}
}
