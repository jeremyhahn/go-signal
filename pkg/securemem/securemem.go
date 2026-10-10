// Package securemem owns the process lifecycle of go-qrdb's protected memory
// for every go-signal binary.
//
// go-qrdb's secure SDK leaves three steps to the binary that owns the
// process: harden it against inspection (secure.HardenProcess) before any
// protected memory exists, install the process-wide locked-memory budget
// (secure.SetAllocator) before the first protected allocation, and wipe every
// live protected allocation on an orderly shutdown (secure.WipeAll). Run does
// all three around the binary's work. go-qrdb's cmd/qrdbd start command is
// the reference wiring this package follows.
package securemem

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"time"

	"github.com/jeremyhahn/go-qrdb/sdk/go/secure"
)

const (
	// defaultBudgetBytes is the budget installed when the host's
	// RLIMIT_MEMLOCK leaves room for it, and the ceiling of a budget derived
	// from a smaller limit. It matches go-qrdb's DefaultSecureMemoryBudgetMiB
	// (64 MiB): ample for KB-scale keys, credentials and PINs with headroom
	// for concurrent traffic, while still bounding what callers can drive the
	// process to mlock.
	defaultBudgetBytes int64 = 64 << 20

	// headroomBytes is the part of a bounded RLIMIT_MEMLOCK a derived budget
	// leaves for locked memory the process allocator does not account for —
	// sealing a secure.Secret and the Sealer's own key material lock pages
	// against the same per-process ceiling, outside the budget. All of it is
	// page-scale, so 2 MiB is generous while still leaving the budget three
	// quarters of a stock 8 MiB container limit.
	headroomBytes int64 = 2 << 20

	// minBudgetBytes is the smallest budget a derivation may settle on. Below
	// it the process refuses to start rather than fail later, under load, with
	// an ErrBudgetExhausted far from the host setting that caused it.
	minBudgetBytes int64 = 1 << 20
)

// wipeTimeout bounds the shutdown wipe, so a protected allocation whose
// borrow is never released cannot hold the process open indefinitely. It is a
// variable only so tests can bound a wipe without waiting for it.
var wipeTimeout = 30 * time.Second

// The SDK's process-lifecycle calls are irreversible for the calling
// process — hardening cannot be undone, the allocator installs once, and the
// wipe destroys the Sealer's keys — so they are reached through these seams,
// which tests replace.
var (
	hardenProcess             = secure.HardenProcess
	discoverLockedMemoryLimit = secure.DiscoverLockedMemoryLimit
	newAllocator              = secure.NewAllocatorWithinRLimit
	setAllocator              = secure.SetAllocator
	processAllocator          = secure.ProcessAllocator
	wipeAll                   = secure.WipeAll
)

// budgetSource names how resolveBudget arrived at a budget, for the startup
// log line.
type budgetSource string

const (
	// budgetDefault: the host either has no binding memlock ceiling or has
	// room for the full default.
	budgetDefault budgetSource = "default"

	// budgetDerived: a binding RLIMIT_MEMLOCK below the default plus headroom
	// sized the budget.
	budgetDerived budgetSource = "derived from RLIMIT_MEMLOCK"
)

// budget is a resolved locked-memory budget and the facts it was resolved
// from.
type budget struct {
	bytes  int64
	source budgetSource
	limit  secure.LockedMemoryLimit
}

// hardeningLogLevel is the level each hardening outcome is logged at. An
// outcome that leaves the process inspectable is a warning; anything absent
// from the map is informational.
var hardeningLogLevel = map[secure.ProcessHardening]slog.Level{
	secure.ProcessInspectionAllowed:    slog.LevelWarn,
	secure.ProcessHardeningUnavailable: slog.LevelWarn,
}

// Run hardens the process, installs the locked-memory budget, runs fn, and
// wipes every live protected allocation once fn returns.
//
// Every go-signal main calls Run first and does all of its work inside fn:
// configuration loading seals secrets before any command runs, so nothing may
// come earlier. A hardening or budget failure returns before fn runs, and the
// caller must exit non-zero — the process holds no secrets yet and must not
// acquire any unhardened or unbudgeted. An incomplete shutdown wipe is
// reported as a *WipeError unless fn already failed; fn's error is the one
// the caller acts on.
func Run(fn func() error) (err error) {
	if err := harden(); err != nil {
		return err
	}
	if err := installBudget(); err != nil {
		return err
	}
	defer wipe(&err)
	return fn()
}

// harden applies secure.HardenProcess and logs its outcome. Every error it
// returns means the process is not hardened; it is returned as the SDK
// reports it, as go-qrdb's reference does.
func harden() error {
	outcome, err := hardenProcess(slog.Default())
	if err != nil {
		return err
	}
	level, ok := hardeningLogLevel[outcome]
	if !ok {
		level = slog.LevelInfo
	}
	slog.Log(context.Background(), level, "process hardening applied",
		"outcome", outcome.String(),
		"inspection_opt_out_env", secure.AllowProcessInspectionEnv,
	)
	return nil
}

// installBudget resolves the locked-memory budget and installs it as the
// process allocator.
//
// secure.ErrAllocatorInstalled is not fatal by itself: a budget installed
// earlier in the process is benign when its limit equals the resolved one.
// Any other limit is a *BudgetMismatchError, since every protected
// allocation would otherwise run against a figure nobody chose.
func installBudget() error {
	resolved, err := resolveBudget()
	if err != nil {
		return err
	}
	alloc, err := newAllocator(resolved.bytes)
	if err != nil {
		return &BudgetError{BudgetBytes: resolved.bytes, Err: err}
	}
	if err := setAllocator(alloc); err != nil {
		if !errors.Is(err, secure.ErrAllocatorInstalled) {
			return &BudgetError{BudgetBytes: resolved.bytes, Err: err}
		}
		installed, err := processAllocator()
		if err != nil {
			return &BudgetError{BudgetBytes: resolved.bytes, Err: err}
		}
		if installedBytes := installed.Limit(); installedBytes != resolved.bytes {
			return &BudgetError{BudgetBytes: resolved.bytes, Err: &BudgetMismatchError{
				BudgetBytes:    resolved.bytes,
				InstalledBytes: installedBytes,
			}}
		}
	}
	slog.Info("secure memory budget installed",
		"budget_bytes", resolved.bytes,
		"source", string(resolved.source),
		"rlimit_memlock_source", resolved.limit.Source.String(),
		"rlimit_memlock_bytes", resolved.limit.Bytes,
	)
	return nil
}

// resolveBudget derives the budget from the host: min(defaultBudgetBytes,
// RLIMIT_MEMLOCK minus headroomBytes), rounded down to whole pages. A
// ceiling that is unlimited, or not enforced because the process holds
// CAP_IPC_LOCK, binds nothing, so the full default applies. A ceiling too
// small to leave minBudgetBytes fails closed with *LimitTooSmallError, and a
// ceiling that cannot be read fails closed with the discovery error: in
// neither case is there a budget the process could honestly claim to enforce.
func resolveBudget() (budget, error) {
	limit, err := discoverLockedMemoryLimit()
	if err != nil {
		return budget{}, &BudgetError{Err: err}
	}
	if !limit.Bounded {
		return budget{bytes: defaultBudgetBytes, source: budgetDefault, limit: limit}, nil
	}
	derived := limit.Bytes - headroomBytes
	if derived >= defaultBudgetBytes {
		return budget{bytes: defaultBudgetBytes, source: budgetDefault, limit: limit}, nil
	}
	if page := int64(os.Getpagesize()); derived > 0 {
		derived -= derived % page
	}
	if derived < minBudgetBytes {
		return budget{}, &BudgetError{Err: &LimitTooSmallError{
			LimitBytes:    limit.Bytes,
			HeadroomBytes: headroomBytes,
			MinimumBytes:  minBudgetBytes,
		}}
	}
	return budget{bytes: derived, source: budgetDerived, limit: limit}, nil
}

// wipe destroys every live protected allocation, bounded by wipeTimeout, and
// reports an incomplete wipe through err without overwriting an earlier
// failure.
func wipe(err *error) {
	ctx, cancel := context.WithTimeout(context.Background(), wipeTimeout)
	defer cancel()
	remaining, werr := wipeAll(ctx)
	if remaining == 0 && werr == nil {
		return
	}
	wipeErr := &WipeError{Remaining: remaining, Err: werr}
	slog.Error("secure memory wipe incomplete at shutdown", "error", wipeErr)
	if *err == nil {
		*err = wipeErr
	}
}
