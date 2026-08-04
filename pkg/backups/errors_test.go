package backups_test

import (
	"strings"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/backups"
)

// TestErrors_FormatStrings exercises every Error() method so the package's
// error surface is fully covered and any future formatting regressions
// surface as test failures rather than silent log gaps.
func TestErrors_FormatStrings(t *testing.T) {
	var id backups.BackupID
	for i := range id {
		id[i] = byte(i + 1)
	}
	cases := []struct {
		name     string
		err      error
		contains string
	}{
		{"PermissionError", &backups.PermissionError{Required: backups.BackupLevelPaid, Got: backups.BackupLevelFree}, "does not authorize"},
		{"WrongCredentialTypeError", &backups.WrongCredentialTypeError{Required: backups.CredentialTypeMedia, Got: backups.CredentialTypeMessages}, "cannot be used"},
		{"FailedZkAuthError", &backups.FailedZkAuthError{Reason: "bad sig"}, "verification failed"},
		{"PublicKeyConflictError", &backups.PublicKeyConflictError{BackupID: id}, "public key conflict"},
		{"NotFoundError", &backups.NotFoundError{BackupID: id}, "backup not found"},
		{"InvalidArgumentError", &backups.InvalidArgumentError{Field: "f", Message: "m"}, "invalid argument"},
		{"RateLimitedError", &backups.RateLimitedError{Limit: "x", RetryAfter: 60}, "rate limit"},
		{"SourceNotFoundError", &backups.SourceNotFoundError{SourceKey: "k"}, "source object not found"},
		{"InvalidLengthError", &backups.InvalidLengthError{SourceKey: "k", Expected: 1, Actual: 2}, "source length mismatch"},
		{"BadReceiptError", &backups.BadReceiptError{Reason: "expired"}, "bad backup receipt"},
		{"MissingIDCommitmentError", &backups.MissingIDCommitmentError{}, "no media credential request"},
		{"PendingDeletionError", &backups.PendingDeletionError{BackupID: id}, "deletion already pending"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			msg := c.err.Error()
			if !strings.Contains(msg, c.contains) {
				t.Errorf("error message %q missing %q", msg, c.contains)
			}
		})
	}
}
