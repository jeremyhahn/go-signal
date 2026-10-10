package securemem

import "strconv"

// BudgetError reports that the process locked-memory budget could not be
// resolved or installed. The process must not continue: without an installed
// budget nothing bounds what protected allocations may mlock.
type BudgetError struct {
	// BudgetBytes is the budget that was being installed, or zero when the
	// failure came before one was resolved.
	BudgetBytes int64
	Err         error
}

func (e *BudgetError) Error() string {
	if e.BudgetBytes == 0 {
		return "securemem: locked-memory budget: " + e.Err.Error()
	}
	return "securemem: locked-memory budget of " + strconv.FormatInt(e.BudgetBytes, 10) +
		" bytes: " + e.Err.Error()
}

func (e *BudgetError) Unwrap() error { return e.Err }

// LimitTooSmallError reports a bounded RLIMIT_MEMLOCK too small to leave the
// minimum budget once the headroom for unbudgeted locked memory is set aside.
// The remedy is a host memlock limit (ulimit -l, or the container's memlock
// ulimit) of at least HeadroomBytes plus MinimumBytes.
type LimitTooSmallError struct {
	LimitBytes    int64
	HeadroomBytes int64
	MinimumBytes  int64
}

func (e *LimitTooSmallError) Error() string {
	return "securemem: RLIMIT_MEMLOCK of " + strconv.FormatInt(e.LimitBytes, 10) +
		" bytes leaves less than the minimum budget of " + strconv.FormatInt(e.MinimumBytes, 10) +
		" bytes after " + strconv.FormatInt(e.HeadroomBytes, 10) + " bytes of headroom"
}

// BudgetMismatchError reports that a process allocator was already installed
// with a limit other than the budget this package resolved. Continuing would
// run every protected allocation against a figure nobody chose.
type BudgetMismatchError struct {
	BudgetBytes    int64
	InstalledBytes int64
}

func (e *BudgetMismatchError) Error() string {
	return "securemem: process allocator already installed with " +
		strconv.FormatInt(e.InstalledBytes, 10) + " bytes, want " +
		strconv.FormatInt(e.BudgetBytes, 10)
}

// WipeError reports an incomplete shutdown wipe: Remaining protected
// allocations were still live when the wipe ended, or Err reports that the
// wipe was cut short or detected corruption.
type WipeError struct {
	Remaining int
	Err       error
}

func (e *WipeError) Error() string {
	msg := "securemem: shutdown wipe left " + strconv.Itoa(e.Remaining) + " protected allocations live"
	if e.Err != nil {
		msg += ": " + e.Err.Error()
	}
	return msg
}

func (e *WipeError) Unwrap() error { return e.Err }
