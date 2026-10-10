package securemem

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/jeremyhahn/go-qrdb/sdk/go/secure"
)

// errUnstubbedSeam is what every seam returns unless a test installs its own
// double: the real calls harden the test binary, read the host's
// RLIMIT_MEMLOCK, install its one allocator and destroy the Sealer's keys,
// none of which a test may do.
var errUnstubbedSeam = errors.New("securemem_test: unstubbed lifecycle seam")

func TestMain(m *testing.M) {
	hardenProcess = func(*slog.Logger) (secure.ProcessHardening, error) { return 0, errUnstubbedSeam }
	discoverLockedMemoryLimit = func() (secure.LockedMemoryLimit, error) {
		return secure.LockedMemoryLimit{}, errUnstubbedSeam
	}
	newAllocator = func(int64) (*secure.Allocator, error) { return nil, errUnstubbedSeam }
	setAllocator = func(*secure.Allocator) error { return errUnstubbedSeam }
	processAllocator = func() (*secure.Allocator, error) { return nil, errUnstubbedSeam }
	allocatorLimit = func(*secure.Allocator) int64 { return -1 }
	wipeAll = func(context.Context) (int, error) { return 0, errUnstubbedSeam }
	os.Exit(m.Run())
}

// lifecycle records the order the seams are reached in and lets a test
// override any one of them.
type lifecycle struct {
	calls []string

	hardening      secure.ProcessHardening
	hardenErr      error
	limit          secure.LockedMemoryLimit
	limitErr       error
	allocErr       error
	setErr         error
	installedErr   error
	installedLimit int64
	wipe           func(context.Context) (int, error)
	budget         int64
}

// stubLifecycle installs doubles for every seam for the duration of t, with
// a clean default: hardened, an unbounded memlock ceiling, an allocator that
// installs, and a complete wipe. No double reads the host: the memlock
// ceiling and every allocator limit are the figures the test sets.
func stubLifecycle(t *testing.T) *lifecycle {
	t.Helper()
	l := &lifecycle{
		hardening: secure.ProcessHardened,
		limit:     secure.LockedMemoryLimit{Source: secure.LimitUnlimited},
		wipe:      func(context.Context) (int, error) { return 0, nil },
	}
	prevHarden, prevDiscover, prevNew, prevSet, prevProcess, prevLimit, prevWipe :=
		hardenProcess, discoverLockedMemoryLimit, newAllocator, setAllocator, processAllocator, allocatorLimit, wipeAll
	t.Cleanup(func() {
		hardenProcess, discoverLockedMemoryLimit, newAllocator, setAllocator, processAllocator, allocatorLimit, wipeAll =
			prevHarden, prevDiscover, prevNew, prevSet, prevProcess, prevLimit, prevWipe
	})
	hardenProcess = func(*slog.Logger) (secure.ProcessHardening, error) {
		l.calls = append(l.calls, "harden")
		return l.hardening, l.hardenErr
	}
	discoverLockedMemoryLimit = func() (secure.LockedMemoryLimit, error) {
		l.calls = append(l.calls, "discover")
		return l.limit, l.limitErr
	}
	newAllocator = func(n int64) (*secure.Allocator, error) {
		l.calls = append(l.calls, "newAllocator")
		l.budget = n
		return nil, l.allocErr
	}
	setAllocator = func(*secure.Allocator) error {
		l.calls = append(l.calls, "setAllocator")
		return l.setErr
	}
	processAllocator = func() (*secure.Allocator, error) {
		l.calls = append(l.calls, "processAllocator")
		return nil, l.installedErr
	}
	allocatorLimit = func(*secure.Allocator) int64 { return l.installedLimit }
	wipeAll = func(ctx context.Context) (int, error) {
		l.calls = append(l.calls, "wipe")
		return l.wipe(ctx)
	}
	return l
}

// newTestLifecycle returns a Lifecycle whose logger writes JSON records to
// the returned buffer.
func newTestLifecycle() (*Lifecycle, *bytes.Buffer) {
	var buf bytes.Buffer
	return New(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))), &buf
}

// logRecords decodes the JSON records in buf, keyed by message.
func logRecords(t *testing.T, buf *bytes.Buffer) map[string]map[string]any {
	t.Helper()
	records := map[string]map[string]any{}
	dec := json.NewDecoder(buf)
	for dec.More() {
		var rec map[string]any
		if err := dec.Decode(&rec); err != nil {
			t.Fatalf("decode log record: %v", err)
		}
		msg, _ := rec[slog.MessageKey].(string)
		records[msg] = rec
	}
	return records
}

// startAndRun is the shape of a secret-bearing command: Start, then work.
func startAndRun(lc *Lifecycle, l *lifecycle, work func() error) func() error {
	return func() error {
		if err := lc.Start(); err != nil {
			return err
		}
		l.calls = append(l.calls, "fn")
		return work()
	}
}

func TestRun_StartupOrder(t *testing.T) {
	l := stubLifecycle(t)
	lc, _ := newTestLifecycle()
	if err := lc.Run(startAndRun(lc, l, func() error { return nil })); err != nil {
		t.Fatalf("Run: %v", err)
	}
	want := []string{"harden", "discover", "newAllocator", "setAllocator", "fn", "wipe"}
	if !slices.Equal(l.calls, want) {
		t.Fatalf("calls = %v, want %v", l.calls, want)
	}
	if l.budget != defaultBudgetBytes {
		t.Errorf("budget = %d, want %d", l.budget, defaultBudgetBytes)
	}
}

// TestRun_WithoutStartTouchesNothing is the secret-free command path
// (version, help): with a memlock ceiling too small to budget, the command
// still runs, and the process is neither hardened, budgeted nor wiped.
func TestRun_WithoutStartTouchesNothing(t *testing.T) {
	l := stubLifecycle(t)
	l.limit = secure.LockedMemoryLimit{Bytes: 0, Bounded: true}
	lc, buf := newTestLifecycle()
	ran := false
	if err := lc.Run(func() error { ran = true; return nil }); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !ran {
		t.Error("fn did not run")
	}
	if len(l.calls) != 0 {
		t.Errorf("calls = %v, want none", l.calls)
	}
	if buf.Len() != 0 {
		t.Errorf("a secret-free run logged %q", buf.String())
	}
}

func TestRun_WithoutStartReturnsFnError(t *testing.T) {
	l := stubLifecycle(t)
	lc, _ := newTestLifecycle()
	fnErr := errors.New("version failed")
	if err := lc.Run(func() error { return fnErr }); !errors.Is(err, fnErr) {
		t.Fatalf("Run error = %v, want %v", err, fnErr)
	}
	if slices.Contains(l.calls, "wipe") {
		t.Errorf("calls = %v: a process that never started must not wipe", l.calls)
	}
}

func TestRun_ReturnsFnErrorAfterWiping(t *testing.T) {
	l := stubLifecycle(t)
	lc, _ := newTestLifecycle()
	fnErr := errors.New("fn failed")
	err := lc.Run(startAndRun(lc, l, func() error { return fnErr }))
	if !errors.Is(err, fnErr) {
		t.Fatalf("Run error = %v, want %v", err, fnErr)
	}
	if l.calls[len(l.calls)-1] != "wipe" {
		t.Errorf("calls = %v, want the wipe last", l.calls)
	}
}

func TestRun_WipesWhenFnPanics(t *testing.T) {
	l := stubLifecycle(t)
	lc, _ := newTestLifecycle()
	defer func() {
		if recover() == nil {
			t.Fatal("panic was not propagated")
		}
		if l.calls[len(l.calls)-1] != "wipe" {
			t.Errorf("calls = %v, want the wipe last", l.calls)
		}
	}()
	_ = lc.Run(startAndRun(lc, l, func() error { panic("fn panicked") }))
}

func TestStart_Idempotent(t *testing.T) {
	l := stubLifecycle(t)
	lc, _ := newTestLifecycle()
	for range 3 {
		if err := lc.Start(); err != nil {
			t.Fatalf("Start: %v", err)
		}
	}
	want := []string{"harden", "discover", "newAllocator", "setAllocator"}
	if !slices.Equal(l.calls, want) {
		t.Fatalf("calls = %v, want one hardening and one budget %v", l.calls, want)
	}
}

func TestStart_HardeningFailureStopsBeforeAnythingElse(t *testing.T) {
	hardenErrs := map[string]error{
		"traced":          &secure.ProcessTracedError{},
		"hardening":       &secure.ProcessHardeningError{},
		"opt-out":         &secure.ProcessInspectionOptOutError{},
		"opt-out in FIPS": &secure.ProcessInspectionOptOutRefusedError{},
	}
	for name, hardenErr := range hardenErrs {
		t.Run(name, func(t *testing.T) {
			l := stubLifecycle(t)
			l.hardenErr = hardenErr
			lc, _ := newTestLifecycle()
			ran := false
			err := lc.Run(func() error {
				if err := lc.Start(); err != nil {
					return err
				}
				ran = true
				return nil
			})
			if !errors.Is(err, hardenErr) {
				t.Fatalf("Run error = %v, want the hardening error unchanged", err)
			}
			if ran {
				t.Error("work ran in an unhardened process")
			}
			if !slices.Equal(l.calls, []string{"harden"}) {
				t.Errorf("calls = %v, want only harden", l.calls)
			}
		})
	}
}

func TestStart_HardeningOutcomesProceed(t *testing.T) {
	outcomes := map[secure.ProcessHardening]string{
		secure.ProcessHardened:             slog.LevelInfo.String(),
		secure.ProcessInspectionAllowed:    slog.LevelWarn.String(),
		secure.ProcessHardeningUnavailable: slog.LevelWarn.String(),
	}
	for outcome, level := range outcomes {
		t.Run(outcome.String(), func(t *testing.T) {
			l := stubLifecycle(t)
			l.hardening = outcome
			lc, buf := newTestLifecycle()
			if err := lc.Start(); err != nil {
				t.Fatalf("Start: %v", err)
			}
			rec, ok := logRecords(t, buf)["process hardening applied"]
			if !ok {
				t.Fatal("hardening outcome not logged through the lifecycle's logger")
			}
			if rec[slog.LevelKey] != level || rec["outcome"] != outcome.String() {
				t.Errorf("record = %v, want level %s outcome %s", rec, level, outcome)
			}
		})
	}
}

// TestStart_LogsThroughTheGivenLogger proves both startup records reach the
// logger main built, in its format, and the SDK's hardening call receives it.
func TestStart_LogsThroughTheGivenLogger(t *testing.T) {
	l := stubLifecycle(t)
	lc, buf := newTestLifecycle()
	var hardenLogger *slog.Logger
	hardenProcess = func(logger *slog.Logger) (secure.ProcessHardening, error) {
		hardenLogger = logger
		return l.hardening, nil
	}
	if err := lc.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if hardenLogger != lc.logger {
		t.Error("secure.HardenProcess did not receive the lifecycle's logger")
	}
	rec, ok := logRecords(t, buf)["secure memory budget installed"]
	if !ok {
		t.Fatal("budget not logged through the lifecycle's logger")
	}
	if rec["budget_bytes"] != float64(defaultBudgetBytes) || rec["source"] != string(budgetDefault) {
		t.Errorf("record = %v, want budget %d from %s", rec, defaultBudgetBytes, budgetDefault)
	}
}

func TestStart_BudgetFailureStopsBeforeWork(t *testing.T) {
	l := stubLifecycle(t)
	l.allocErr = secure.ErrBudgetExceedsRLimit
	lc, _ := newTestLifecycle()
	ran := false
	err := lc.Run(func() error {
		if err := lc.Start(); err != nil {
			return err
		}
		ran = true
		return nil
	})
	var budgetErr *BudgetError
	if !errors.As(err, &budgetErr) {
		t.Fatalf("Run error = %v (%T), want *BudgetError", err, err)
	}
	if !errors.Is(err, secure.ErrBudgetExceedsRLimit) {
		t.Error("BudgetError does not unwrap to the allocator error")
	}
	if budgetErr.BudgetBytes != defaultBudgetBytes {
		t.Errorf("BudgetBytes = %d, want %d", budgetErr.BudgetBytes, defaultBudgetBytes)
	}
	if ran {
		t.Error("work ran without an installed budget")
	}
	if slices.Contains(l.calls, "wipe") {
		t.Errorf("calls = %v: a startup that never installed a budget must not wipe", l.calls)
	}
}

func TestInstallBudget_SetAllocatorFailure(t *testing.T) {
	l := stubLifecycle(t)
	sentinel := errors.New("set allocator refused")
	l.setErr = sentinel
	lc, _ := newTestLifecycle()
	err := lc.installBudget()
	var budgetErr *BudgetError
	if !errors.As(err, &budgetErr) || !errors.Is(err, sentinel) {
		t.Fatalf("installBudget error = %v, want *BudgetError wrapping %v", err, sentinel)
	}
	if slices.Contains(l.calls, "processAllocator") {
		t.Error("a non-ErrAllocatorInstalled failure consulted the installed allocator")
	}
}

func TestInstallBudget_AlreadyInstalledMatching(t *testing.T) {
	l := stubLifecycle(t)
	l.setErr = secure.ErrAllocatorInstalled
	l.installedLimit = defaultBudgetBytes
	lc, _ := newTestLifecycle()
	if err := lc.installBudget(); err != nil {
		t.Fatalf("installBudget with a matching installed allocator: %v", err)
	}
	if !slices.Contains(l.calls, "processAllocator") {
		t.Errorf("calls = %v, want the installed allocator consulted", l.calls)
	}
}

func TestInstallBudget_AlreadyInstalledMismatch(t *testing.T) {
	l := stubLifecycle(t)
	l.setErr = secure.ErrAllocatorInstalled
	l.installedLimit = defaultBudgetBytes + int64(os.Getpagesize())
	lc, _ := newTestLifecycle()
	err := lc.installBudget()
	var mismatch *BudgetMismatchError
	if !errors.As(err, &mismatch) {
		t.Fatalf("installBudget error = %v (%T), want *BudgetMismatchError", err, err)
	}
	if mismatch.BudgetBytes != defaultBudgetBytes || mismatch.InstalledBytes != l.installedLimit {
		t.Errorf("mismatch = %+v, want budget %d installed %d", mismatch, defaultBudgetBytes, l.installedLimit)
	}
}

func TestInstallBudget_InstalledAllocatorUnreadable(t *testing.T) {
	l := stubLifecycle(t)
	l.setErr = secure.ErrAllocatorInstalled
	l.installedErr = secure.ErrNilAllocator
	lc, _ := newTestLifecycle()
	err := lc.installBudget()
	var budgetErr *BudgetError
	if !errors.As(err, &budgetErr) || !errors.Is(err, secure.ErrNilAllocator) {
		t.Fatalf("installBudget error = %v, want *BudgetError wrapping ErrNilAllocator", err)
	}
}

func TestResolveBudget(t *testing.T) {
	page := int64(os.Getpagesize())
	tests := map[string]struct {
		limit  secure.LockedMemoryLimit
		bytes  int64
		source budgetSource
	}{
		"unbounded": {
			limit:  secure.LockedMemoryLimit{Source: secure.LimitUnlimited},
			bytes:  defaultBudgetBytes,
			source: budgetDefault,
		},
		"room for the default": {
			limit:  secure.LockedMemoryLimit{Bytes: defaultBudgetBytes + headroomBytes, Bounded: true},
			bytes:  defaultBudgetBytes,
			source: budgetDefault,
		},
		"derived from a stock container limit": {
			limit:  secure.LockedMemoryLimit{Bytes: 8 << 20, Bounded: true},
			bytes:  8<<20 - headroomBytes,
			source: budgetDerived,
		},
		"derived and rounded down to a page": {
			limit:  secure.LockedMemoryLimit{Bytes: 8<<20 + page/2, Bounded: true},
			bytes:  8<<20 - headroomBytes,
			source: budgetDerived,
		},
		"exactly the minimum": {
			limit:  secure.LockedMemoryLimit{Bytes: minBudgetBytes + headroomBytes, Bounded: true},
			bytes:  minBudgetBytes,
			source: budgetDerived,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			l := stubLifecycle(t)
			l.limit = tc.limit
			got, err := resolveBudget()
			if err != nil {
				t.Fatalf("resolveBudget: %v", err)
			}
			if got.bytes != tc.bytes || got.source != tc.source {
				t.Errorf("budget = %d (%s), want %d (%s)", got.bytes, got.source, tc.bytes, tc.source)
			}
		})
	}
}

func TestResolveBudget_LimitTooSmall(t *testing.T) {
	limits := map[string]int64{
		"zero":               0,
		"below the minimum":  minBudgetBytes + headroomBytes - 1,
		"below the headroom": headroomBytes / 2,
	}
	for name, limitBytes := range limits {
		t.Run(name, func(t *testing.T) {
			l := stubLifecycle(t)
			l.limit = secure.LockedMemoryLimit{Bytes: limitBytes, Bounded: true}
			_, err := resolveBudget()
			var tooSmall *LimitTooSmallError
			if !errors.As(err, &tooSmall) {
				t.Fatalf("resolveBudget error = %v (%T), want *LimitTooSmallError", err, err)
			}
			if tooSmall.LimitBytes != limitBytes {
				t.Errorf("LimitBytes = %d, want %d", tooSmall.LimitBytes, limitBytes)
			}
			if slices.Contains(l.calls, "newAllocator") {
				t.Error("an allocator was built for a limit too small to budget")
			}
		})
	}
}

func TestResolveBudget_DiscoveryFailureFailsClosed(t *testing.T) {
	l := stubLifecycle(t)
	l.limitErr = secure.ErrLimitDiscoveryFailed
	_, err := resolveBudget()
	var budgetErr *BudgetError
	if !errors.As(err, &budgetErr) || !errors.Is(err, secure.ErrLimitDiscoveryFailed) {
		t.Fatalf("resolveBudget error = %v, want *BudgetError wrapping ErrLimitDiscoveryFailed", err)
	}
}

// startedLifecycle returns a Lifecycle whose Start has succeeded against
// the stubbed seams.
func startedLifecycle(t *testing.T) (*Lifecycle, *bytes.Buffer) {
	t.Helper()
	lc, buf := newTestLifecycle()
	if err := lc.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	buf.Reset()
	return lc, buf
}

func TestWipe_BoundedByItsContext(t *testing.T) {
	l := stubLifecycle(t)
	lc, _ := startedLifecycle(t)
	prev := wipeTimeout
	wipeTimeout = 10 * time.Millisecond
	t.Cleanup(func() { wipeTimeout = prev })
	l.wipe = func(ctx context.Context) (int, error) {
		if _, ok := ctx.Deadline(); !ok {
			t.Error("wipe context has no deadline")
		}
		<-ctx.Done()
		return 2, ctx.Err()
	}

	done := make(chan error, 1)
	go func() {
		var err error
		lc.wipe(&err)
		done <- err
	}()
	select {
	case err := <-done:
		var wipeErr *WipeError
		if !errors.As(err, &wipeErr) || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("wipe error = %v, want *WipeError wrapping context.DeadlineExceeded", err)
		}
		if wipeErr.Remaining != 2 {
			t.Errorf("Remaining = %d, want 2", wipeErr.Remaining)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("wipe was not bounded by its context")
	}
}

func TestWipe_DefaultTimeoutIsTheReference(t *testing.T) {
	l := stubLifecycle(t)
	lc, _ := startedLifecycle(t)
	l.wipe = func(ctx context.Context) (int, error) {
		deadline, ok := ctx.Deadline()
		if !ok {
			t.Fatal("wipe context has no deadline")
		}
		if left := time.Until(deadline); left <= 0 || left > 30*time.Second {
			t.Errorf("wipe deadline in %v, want within 30s", left)
		}
		return 0, nil
	}
	var err error
	lc.wipe(&err)
	if err != nil {
		t.Fatalf("a clean wipe set err = %v", err)
	}
}

func TestWipe_IncompleteSurfacesOnACleanRun(t *testing.T) {
	l := stubLifecycle(t)
	lc, buf := startedLifecycle(t)
	l.wipe = func(context.Context) (int, error) { return 3, nil }
	err := lc.Run(func() error { return nil })
	var wipeErr *WipeError
	if !errors.As(err, &wipeErr) {
		t.Fatalf("Run error = %v (%T), want *WipeError", err, err)
	}
	if wipeErr.Remaining != 3 {
		t.Errorf("Remaining = %d, want 3", wipeErr.Remaining)
	}
	rec, ok := logRecords(t, buf)["secure memory wipe incomplete at shutdown"]
	if !ok || rec[slog.LevelKey] != slog.LevelError.String() {
		t.Errorf("incomplete wipe not logged as an error through the lifecycle's logger: %v", rec)
	}
}

func TestWipe_DoesNotOverwriteAnEarlierError(t *testing.T) {
	l := stubLifecycle(t)
	lc, _ := startedLifecycle(t)
	l.wipe = func(context.Context) (int, error) { return 5, nil }
	original := errors.New("server failed")
	err := lc.Run(func() error { return original })
	if !errors.Is(err, original) {
		t.Fatalf("Run error = %v, want the original %v", err, original)
	}
}

func TestErrors_Messages(t *testing.T) {
	cause := errors.New("cause")
	tests := map[string]struct {
		err  error
		want string
	}{
		"budget without bytes": {
			err:  &BudgetError{Err: cause},
			want: "securemem: locked-memory budget: cause",
		},
		"budget with bytes": {
			err:  &BudgetError{BudgetBytes: 4096, Err: cause},
			want: "securemem: locked-memory budget of 4096 bytes: cause",
		},
		"limit too small": {
			err:  &LimitTooSmallError{LimitBytes: 65536, HeadroomBytes: 2, MinimumBytes: 1},
			want: "securemem: RLIMIT_MEMLOCK of 65536 bytes leaves less than the minimum budget of 1 bytes after 2 bytes of headroom",
		},
		"mismatch": {
			err:  &BudgetMismatchError{BudgetBytes: 1, InstalledBytes: 2},
			want: "securemem: process allocator already installed with 2 bytes, want 1",
		},
		"wipe incomplete": {
			err:  &WipeError{Remaining: 3},
			want: "securemem: shutdown wipe left 3 protected allocations live",
		},
		"wipe failed": {
			err:  &WipeError{Remaining: 1, Err: cause},
			want: "securemem: shutdown wipe left 1 protected allocations live: cause",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if got := tc.err.Error(); got != tc.want {
				t.Errorf("Error() = %q, want %q", got, tc.want)
			}
		})
	}
}
