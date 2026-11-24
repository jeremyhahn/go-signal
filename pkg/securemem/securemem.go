// Package securemem hardens the process, installs the locked-memory budget and wipes protected memory on shutdown for every go-signal binary.
package securemem

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-qrdb/sdk/go/secure"
)

const (
	// defaultBudgetBytes is the locked-memory budget (64 MiB), and the ceiling of one derived from a smaller limit.
	defaultBudgetBytes int64 = 64 << 20

	// headroomBytes is the part of RLIMIT_MEMLOCK left for locked memory outside the budget.
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

// Seams for the irreversible process calls and the RLIMIT_MEMLOCK read; tests replace them.
var (
	hardenProcess             = secure.HardenProcess
	discoverLockedMemoryLimit = secure.DiscoverLockedMemoryLimit
	newAllocator              = secure.NewAllocatorWithinRLimit
	setAllocator              = secure.SetAllocator
	processAllocator          = secure.ProcessAllocator
	allocatorLimit            = (*secure.Allocator).Limit
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

// Lifecycle is one process's secure-memory lifecycle; call Start before loading config or creating secrets.
type Lifecycle struct {
	logger  *slog.Logger
	started atomic.Bool
}

// New returns the lifecycle of a process whose records go to logger, the
// logger main built for the binary. logger must not be nil.
func New(logger *slog.Logger) *Lifecycle {
	return &Lifecycle{logger: logger}
}

// Start hardens the process and installs the budget once; on failure the command must fail before loading anything.
func (l *Lifecycle) Start() error {
	if l.started.Load() {
		return nil
	}
	if err := l.harden(); err != nil {
		return err
	}
	if err := l.installBudget(); err != nil {
		return err
	}
	l.started.Store(true)
	return nil
}

// Run runs fn and wipes protected memory if Start succeeded; a failed wipe is a *WipeError unless fn failed.
func (l *Lifecycle) Run(fn func() error) (err error) {
	defer l.wipe(&err)
	return fn()
}

// harden applies secure.HardenProcess and logs its outcome. Every error it
// returns means the process is not hardened; it is returned as the SDK
// reports it, as go-qrdb's reference does.
func (l *Lifecycle) harden() error {
	outcome, err := hardenProcess(l.logger)
	if err != nil {
		return err
	}
	level, ok := hardeningLogLevel[outcome]
	if !ok {
		level = slog.LevelInfo
	}
	l.logger.Log(context.Background(), level, "process hardening applied",
		"outcome", outcome.String(),
		"inspection_opt_out_env", secure.AllowProcessInspectionEnv,
	)
	return nil
}

// installBudget installs the resolved budget; an existing allocator with a different limit is *BudgetMismatchError.
func (l *Lifecycle) installBudget() error {
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
		if installedBytes := allocatorLimit(installed); installedBytes != resolved.bytes {
			return &BudgetError{BudgetBytes: resolved.bytes, Err: &BudgetMismatchError{
				BudgetBytes:    resolved.bytes,
				InstalledBytes: installedBytes,
			}}
		}
	}
	l.logger.Info("secure memory budget installed",
		"budget_bytes", resolved.bytes,
		"source", string(resolved.source),
		"rlimit_memlock_source", resolved.limit.Source.String(),
		"rlimit_memlock_bytes", resolved.limit.Bytes,
	)
	return nil
}

// resolveBudget is min(defaultBudgetBytes, RLIMIT_MEMLOCK - headroomBytes) in whole pages; unlimited gets the default, too small or unreadable fails closed.
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

// wipe destroys every live protected allocation of a started process,
// bounded by wipeTimeout, and reports an incomplete wipe through err without
// overwriting an earlier failure.
func (l *Lifecycle) wipe(err *error) {
	if !l.started.Load() {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), wipeTimeout)
	defer cancel()
	remaining, werr := wipeAll(ctx)
	if remaining == 0 && werr == nil {
		return
	}
	wipeErr := &WipeError{Remaining: remaining, Err: werr}
	l.logger.Error("secure memory wipe incomplete at shutdown", "error", wipeErr)
	if *err == nil {
		*err = wipeErr
	}
}
