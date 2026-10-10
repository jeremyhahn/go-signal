package securemem

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/jeremyhahn/go-qrdb/sdk/go/secure"
)

// errUnstubbedSeam is what every seam returns unless a test installs its own
// double: the real calls harden the test binary, install its one allocator
// and destroy the Sealer's keys, none of which a test may do.
var errUnstubbedSeam = errors.New("securemem_test: unstubbed lifecycle seam")

func TestMain(m *testing.M) {
	hardenProcess = func(*slog.Logger) (secure.ProcessHardening, error) { return 0, errUnstubbedSeam }
	discoverLockedMemoryLimit = func() (secure.LockedMemoryLimit, error) {
		return secure.LockedMemoryLimit{}, errUnstubbedSeam
	}
	newAllocator = func(int64) (*secure.Allocator, error) { return nil, errUnstubbedSeam }
	setAllocator = func(*secure.Allocator) error { return errUnstubbedSeam }
	processAllocator = func() (*secure.Allocator, error) { return nil, errUnstubbedSeam }
	wipeAll = func(context.Context) (int, error) { return 0, errUnstubbedSeam }
	os.Exit(m.Run())
}

// lifecycle records the order the seams are reached in and lets a test
// override any one of them.
type lifecycle struct {
	calls []string

	hardening secure.ProcessHardening
	hardenErr error
	limit     secure.LockedMemoryLimit
	limitErr  error
	allocErr  error
	setErr    error
	installed func() (*secure.Allocator, error)
	wipe      func(context.Context) (int, error)
	budget    int64
}

// stubLifecycle installs doubles for every seam for the duration of t, with
// a clean default: hardened, an unbounded memlock ceiling, an allocator that
// installs, and a complete wipe.
func stubLifecycle(t *testing.T) *lifecycle {
	t.Helper()
	l := &lifecycle{
		hardening: secure.ProcessHardened,
		limit:     secure.LockedMemoryLimit{Source: secure.LimitUnlimited},
		wipe:      func(context.Context) (int, error) { return 0, nil },
	}
	prevHarden, prevDiscover, prevNew, prevSet, prevProcess, prevWipe :=
		hardenProcess, discoverLockedMemoryLimit, newAllocator, setAllocator, processAllocator, wipeAll
	t.Cleanup(func() {
		hardenProcess, discoverLockedMemoryLimit, newAllocator, setAllocator, processAllocator, wipeAll =
			prevHarden, prevDiscover, prevNew, prevSet, prevProcess, prevWipe
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
		return l.installed()
	}
	wipeAll = func(ctx context.Context) (int, error) {
		l.calls = append(l.calls, "wipe")
		return l.wipe(ctx)
	}
	return l
}

// allocatorWithLimit builds an allocator reporting limit without installing
// it or locking anything: a one-page budget passes any memlock ceiling, and
// ForceLimit then sets the figure without consulting it.
func allocatorWithLimit(t *testing.T, limit int64) *secure.Allocator {
	t.Helper()
	a, err := secure.NewAllocatorWithinRLimit(int64(os.Getpagesize()))
	if err != nil {
		t.Fatalf("NewAllocatorWithinRLimit: %v", err)
	}
	if _, err := a.ForceLimit(limit); err != nil {
		t.Fatalf("ForceLimit: %v", err)
	}
	return a
}

func TestRun_StartupOrder(t *testing.T) {
	l := stubLifecycle(t)
	err := Run(func() error {
		l.calls = append(l.calls, "fn")
		return nil
	})
	if err != nil {
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

func TestRun_ReturnsFnErrorAfterWiping(t *testing.T) {
	l := stubLifecycle(t)
	fnErr := errors.New("fn failed")
	err := Run(func() error { return fnErr })
	if !errors.Is(err, fnErr) {
		t.Fatalf("Run error = %v, want %v", err, fnErr)
	}
	if l.calls[len(l.calls)-1] != "wipe" {
		t.Errorf("calls = %v, want the wipe last", l.calls)
	}
}

func TestRun_WipesWhenFnPanics(t *testing.T) {
	l := stubLifecycle(t)
	defer func() {
		if recover() == nil {
			t.Fatal("panic was not propagated")
		}
		if l.calls[len(l.calls)-1] != "wipe" {
			t.Errorf("calls = %v, want the wipe last", l.calls)
		}
	}()
	_ = Run(func() error { panic("fn panicked") })
}

func TestRun_HardeningFailureStopsBeforeAnythingElse(t *testing.T) {
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
			ran := false
			err := Run(func() error { ran = true; return nil })
			if !errors.Is(err, hardenErr) {
				t.Fatalf("Run error = %v, want the hardening error unchanged", err)
			}
			if ran {
				t.Error("fn ran in an unhardened process")
			}
			if !slices.Equal(l.calls, []string{"harden"}) {
				t.Errorf("calls = %v, want only harden", l.calls)
			}
		})
	}
}

func TestRun_HardeningOutcomesProceed(t *testing.T) {
	outcomes := []secure.ProcessHardening{
		secure.ProcessHardened,
		secure.ProcessInspectionAllowed,
		secure.ProcessHardeningUnavailable,
	}
	for _, outcome := range outcomes {
		t.Run(outcome.String(), func(t *testing.T) {
			l := stubLifecycle(t)
			l.hardening = outcome
			ran := false
			if err := Run(func() error { ran = true; return nil }); err != nil {
				t.Fatalf("Run: %v", err)
			}
			if !ran {
				t.Error("fn did not run")
			}
		})
	}
}

func TestRun_BudgetFailureStopsBeforeFn(t *testing.T) {
	l := stubLifecycle(t)
	l.allocErr = secure.ErrBudgetExceedsRLimit
	ran := false
	err := Run(func() error { ran = true; return nil })
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
		t.Error("fn ran without an installed budget")
	}
	if slices.Contains(l.calls, "wipe") {
		t.Errorf("calls = %v: a startup that never installed a budget must not wipe", l.calls)
	}
}

func TestInstallBudget_SetAllocatorFailure(t *testing.T) {
	l := stubLifecycle(t)
	sentinel := errors.New("set allocator refused")
	l.setErr = sentinel
	err := installBudget()
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
	installed := allocatorWithLimit(t, defaultBudgetBytes)
	l.installed = func() (*secure.Allocator, error) { return installed, nil }
	if err := installBudget(); err != nil {
		t.Fatalf("installBudget with a matching installed allocator: %v", err)
	}
}

func TestInstallBudget_AlreadyInstalledMismatch(t *testing.T) {
	l := stubLifecycle(t)
	l.setErr = secure.ErrAllocatorInstalled
	installed := allocatorWithLimit(t, defaultBudgetBytes+int64(os.Getpagesize()))
	l.installed = func() (*secure.Allocator, error) { return installed, nil }
	err := installBudget()
	var mismatch *BudgetMismatchError
	if !errors.As(err, &mismatch) {
		t.Fatalf("installBudget error = %v (%T), want *BudgetMismatchError", err, err)
	}
	if mismatch.BudgetBytes != defaultBudgetBytes || mismatch.InstalledBytes != installed.Limit() {
		t.Errorf("mismatch = %+v, want budget %d installed %d", mismatch, defaultBudgetBytes, installed.Limit())
	}
}

func TestInstallBudget_InstalledAllocatorUnreadable(t *testing.T) {
	l := stubLifecycle(t)
	l.setErr = secure.ErrAllocatorInstalled
	l.installed = func() (*secure.Allocator, error) { return nil, secure.ErrNilAllocator }
	err := installBudget()
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

func TestWipe_BoundedByItsContext(t *testing.T) {
	l := stubLifecycle(t)
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
		wipe(&err)
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
	stubLifecycle(t).wipe = func(ctx context.Context) (int, error) {
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
	wipe(&err)
	if err != nil {
		t.Fatalf("a clean wipe set err = %v", err)
	}
}

func TestWipe_IncompleteSurfacesOnACleanRun(t *testing.T) {
	stubLifecycle(t).wipe = func(context.Context) (int, error) { return 3, nil }
	err := Run(func() error { return nil })
	var wipeErr *WipeError
	if !errors.As(err, &wipeErr) {
		t.Fatalf("Run error = %v (%T), want *WipeError", err, err)
	}
	if wipeErr.Remaining != 3 {
		t.Errorf("Remaining = %d, want 3", wipeErr.Remaining)
	}
}

func TestWipe_DoesNotOverwriteAnEarlierError(t *testing.T) {
	stubLifecycle(t).wipe = func(context.Context) (int, error) { return 5, nil }
	original := errors.New("server failed")
	err := Run(func() error { return original })
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
