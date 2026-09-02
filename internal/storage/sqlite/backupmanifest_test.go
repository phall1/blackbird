package sqlite

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func sampleManifest() BackupManifest {
	manifest := BackupManifest{
		FormatVersion: backupFormatVersion,
		CreatedAt:     time.Date(2026, time.August, 15, 12, 0, 0, 0, time.UTC),
		DatabaseBytes: 4096, ApplicationID: ApplicationID, SchemaVersion: SchemaVersion,
		SQLiteVersion: SQLiteVersion, SQLiteSourceID: SQLiteSourceID,
		AuthorityStreams: []BackupAuthorityStream{{
			ScopeKind: "project", ScopeID: "p1", AuthorityID: "a1", AuthorityEpoch: "e1",
			RetainedFromSequence: 1, EventHighWater: 9,
		}},
	}
	manifest.DatabaseSHA256[0] = 0xab
	manifest.SchemaChecksum[sha256.Size-1] = 0x01
	manifest.AuthorityStreams[0].EventHighWaterDigest[5] = 0x7f
	return manifest
}

// The digests are fixed-size arrays, which encoding/json would otherwise render
// as thirty-two numbers apiece. VerifyBackup compares a manifest read back from
// disk against facts re-derived from the snapshot, so every field has to
// survive the round trip byte for byte — including CreatedAt's UTC location,
// which VerifyBackup rejects a manifest for losing.
func TestBackupManifestRoundTripsAsHex(t *testing.T) {
	t.Parallel()

	manifest := sampleManifest()
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, want := range []string{
		`"database_sha256":"ab00`, `"schema_checksum":"0000`, `"event_high_water_digest":"0000`,
		`"format_version":1`, `"authority_streams":[`,
	} {
		if !strings.Contains(string(encoded), want) {
			t.Fatalf("encoded = %s, want it to contain %s", encoded, want)
		}
	}

	var decoded BackupManifest
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !equalBackupManifest(manifest, decoded) {
		t.Fatalf("decoded = %#v, want %#v", decoded, manifest)
	}
	if decoded.CreatedAt.Location() != time.UTC {
		t.Fatalf("created_at location = %v, want UTC", decoded.CreatedAt.Location())
	}
}

func TestBackupManifestRejectsADigestThatIsNotOne(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		encoded string
	}{
		{name: "not hex", encoded: `{"database_sha256":"zz"}`},
		{name: "too short", encoded: `{"database_sha256":"abab"}`},
		{name: "schema checksum too short", encoded: `{"database_sha256":"` +
			strings.Repeat("ab", sha256.Size) + `","schema_checksum":"ab"}`},
		{name: "not an object", encoded: `[]`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var manifest BackupManifest
			if err := json.Unmarshal([]byte(test.encoded), &manifest); err == nil {
				t.Fatalf("json.Unmarshal(%s) = nil, want an error", test.encoded)
			}
		})
	}
}

func TestBackupAuthorityStreamRejectsADigestThatIsNotOne(t *testing.T) {
	t.Parallel()

	var stream BackupAuthorityStream
	if err := json.Unmarshal([]byte(`{"event_high_water_digest":"ab"}`), &stream); err == nil {
		t.Fatal("json.Unmarshal accepted a short authority stream digest")
	}
	if err := json.Unmarshal([]byte(`[]`), &stream); err == nil {
		t.Fatal("json.Unmarshal accepted an authority stream that is not an object")
	}
}

// A snapshot with no companion manifest cannot be restored, so the sidecar is
// published the way the snapshot is: reserved, filled, and renamed into place
// without replacing anything.
func TestWriteBackupManifestPublishesOnceBesideTheSnapshot(t *testing.T) {
	t.Parallel()

	snapshot := filepath.Join(t.TempDir(), "snap.db")
	manifest := sampleManifest()
	if err := WriteBackupManifest(snapshot, manifest); err != nil {
		t.Fatalf("WriteBackupManifest() = %v", err)
	}
	if got := BackupManifestPath(snapshot); got != snapshot+".manifest.json" {
		t.Fatalf("BackupManifestPath() = %q", got)
	}

	read, err := ReadBackupManifest(snapshot)
	if err != nil {
		t.Fatalf("ReadBackupManifest() = %v", err)
	}
	if !equalBackupManifest(manifest, read) {
		t.Fatalf("read = %#v, want %#v", read, manifest)
	}
	info, err := os.Stat(BackupManifestPath(snapshot))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("manifest mode = %v, want 0600", info.Mode().Perm())
	}

	if err := WriteBackupManifest(snapshot, manifest); !errors.Is(err, ErrTargetExists) {
		t.Fatalf("second WriteBackupManifest() = %v, want %v", err, ErrTargetExists)
	}
	// The refused write leaves its reservation behind rather than the published
	// manifest, which is what the backup command's reaper exists to collect.
	entries, err := os.ReadDir(filepath.Dir(snapshot))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("directory holds %d entries, want the manifest and one retained partial", len(entries))
	}
}

func TestReadBackupManifestRejectsWhatItCannotDecode(t *testing.T) {
	t.Parallel()

	snapshot := filepath.Join(t.TempDir(), "snap.db")
	if _, err := ReadBackupManifest(snapshot); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("ReadBackupManifest() with no sidecar = %v, want a not-exist error", err)
	}
	if err := os.WriteFile(BackupManifestPath(snapshot), []byte("{truncated"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadBackupManifest(snapshot); !errors.Is(err, ErrInvalidBackup) {
		t.Fatalf("ReadBackupManifest() with a truncated sidecar = %v, want %v", err, ErrInvalidBackup)
	}
}

// The sidecar is what Restore checks a snapshot against, so a manifest that
// round-tripped through disk has to satisfy VerifyBackup exactly as the one
// Backup returned in memory does.
func TestBackupPublishesAManifestVerifyBackupAccepts(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	root := t.TempDir()
	store, err := Open(ctx, Config{Path: filepath.Join(root, "source.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})

	target := filepath.Join(root, "snapshot.db")
	manifest, err := store.Backup(ctx, target)
	if err != nil {
		t.Fatalf("Backup() = %v", err)
	}
	if err := WriteBackupManifest(target, manifest); err != nil {
		t.Fatalf("WriteBackupManifest() = %v", err)
	}
	read, err := ReadBackupManifest(target)
	if err != nil {
		t.Fatalf("ReadBackupManifest() = %v", err)
	}
	if _, err := VerifyBackup(ctx, target, read); err != nil {
		t.Fatalf("VerifyBackup() with the published manifest = %v", err)
	}
}
