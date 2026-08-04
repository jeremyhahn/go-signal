package messages

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-signal/pkg/store"
)

// newTestKVReportStore returns a KVReportStore backed by an in-memory KVClient
// and exposes the underlying client for low-level test manipulation.
func newTestKVReportStore() (*KVReportStore, *store.MemoryKVClient) {
	kv := store.NewMemoryKVClient()
	return NewKVReportStore(kv), kv
}

// testReport returns a minimal SpamReport with the given reporter UUID.
func testReport(reporterUUID string) *SpamReport {
	return &SpamReport{
		ReporterUUID: reporterUUID,
		SourceUUID:   "source-uuid",
		MessageGUID:  "msg-guid-1",
	}
}

// --- NewKVReportStore ---

func TestNewKVReportStore_NotNil(t *testing.T) {
	s, _ := newTestKVReportStore()
	require.NotNil(t, s)
}

func TestNewKVReportStore_KVAssigned(t *testing.T) {
	kv := store.NewMemoryKVClient()
	s := NewKVReportStore(kv)
	assert.NotNil(t, s.kv)
}

// --- Store ---

func TestKVReportStore_Store_AssignsID(t *testing.T) {
	s, _ := newTestKVReportStore()
	r := testReport("reporter-1")
	require.NoError(t, s.Store(context.Background(), r))
	assert.NotEmpty(t, r.ID)
}

func TestKVReportStore_Store_SetsTimestampWhenZero(t *testing.T) {
	s, _ := newTestKVReportStore()
	r := testReport("reporter-1")
	require.True(t, r.Timestamp.IsZero())
	require.NoError(t, s.Store(context.Background(), r))
	assert.False(t, r.Timestamp.IsZero())
}

func TestKVReportStore_Store_PreservesExistingTimestamp(t *testing.T) {
	s, _ := newTestKVReportStore()
	r := testReport("reporter-1")
	// Use a well-known UTC time to verify it is not overwritten.
	fixedTime := r.Timestamp.Add(0) // zero — but we need a non-zero one:
	_ = fixedTime
	// Store a report with an explicit timestamp set after construction.
	require.NoError(t, s.Store(context.Background(), r))
	// The Timestamp was zero before Store; after Store it must be non-zero.
	// A second report stored immediately after must also have a non-zero ts.
	r2 := testReport("reporter-1")
	r2.Timestamp = r.Timestamp // copy non-zero ts from first report
	require.NoError(t, s.Store(context.Background(), r2))
	assert.Equal(t, r.Timestamp, r2.Timestamp, "pre-set timestamp should not be overwritten")
}

func TestKVReportStore_Store_UniqueIDs(t *testing.T) {
	s, _ := newTestKVReportStore()
	ctx := context.Background()
	r1, r2 := testReport("r"), testReport("r")
	require.NoError(t, s.Store(ctx, r1))
	require.NoError(t, s.Store(ctx, r2))
	assert.NotEqual(t, r1.ID, r2.ID)
}

func TestKVReportStore_Store_MarshalError(t *testing.T) {
	// Substitute the package-level marshal function to simulate a serialisation
	// failure, then restore it so the test does not bleed into other tests.
	orig := reportMarshal
	t.Cleanup(func() { reportMarshal = orig })
	reportMarshal = func(any) ([]byte, error) { return nil, errors.New("marshal failure") }

	s, _ := newTestKVReportStore()
	err := s.Store(context.Background(), testReport("r"))
	require.Error(t, err)

	var rse *ReportStoreError
	require.True(t, errors.As(err, &rse))
	assert.Equal(t, "marshal", rse.Operation)
	assert.Equal(t, "marshal failure", rse.Cause.Error())
}

func TestKVReportStore_Store_PrimaryKeyPutError(t *testing.T) {
	fkv := store.NewFailingKVClient()
	fkv.PutErr = errors.New("put failure")
	s := NewKVReportStore(fkv)

	err := s.Store(context.Background(), testReport("r"))
	require.Error(t, err)

	var rse *ReportStoreError
	require.True(t, errors.As(err, &rse))
	assert.Equal(t, "put", rse.Operation)
	assert.Equal(t, "put failure", rse.Cause.Error())
}

func TestKVReportStore_Store_IndexPutError(t *testing.T) {
	// Allow the first Put (primary) to succeed, fail on the second (index).
	fkv := store.NewFailingKVClient()
	callCount := 0
	// We cannot intercept individual Put calls via FailingKVClient directly,
	// so we use a countingKVClient defined in this test file instead.
	_ = fkv

	ckv := &countingKVClient{delegate: store.NewMemoryKVClient(), failAfter: 1, putFailErr: errors.New("index put failure")}
	s := NewKVReportStore(ckv)
	_ = callCount

	err := s.Store(context.Background(), testReport("r"))
	require.Error(t, err)

	var rse *ReportStoreError
	require.True(t, errors.As(err, &rse))
	assert.Equal(t, "put-index", rse.Operation)
}

// --- GetByReporter ---

func TestKVReportStore_GetByReporter_EmptySlice(t *testing.T) {
	s, _ := newTestKVReportStore()
	results, err := s.GetByReporter(context.Background(), "nobody")
	require.NoError(t, err)
	assert.NotNil(t, results)
	assert.Empty(t, results)
}

func TestKVReportStore_GetByReporter_SingleReport(t *testing.T) {
	s, _ := newTestKVReportStore()
	ctx := context.Background()

	r := testReport("reporter-1")
	require.NoError(t, s.Store(ctx, r))

	results, err := s.GetByReporter(ctx, "reporter-1")
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "msg-guid-1", results[0].MessageGUID)
	assert.Equal(t, "source-uuid", results[0].SourceUUID)
	assert.Equal(t, r.ID, results[0].ID)
}

func TestKVReportStore_GetByReporter_MultipleReports(t *testing.T) {
	s, _ := newTestKVReportStore()
	ctx := context.Background()

	const count = 5
	for i := 0; i < count; i++ {
		require.NoError(t, s.Store(ctx, testReport("reporter-multi")))
	}

	results, err := s.GetByReporter(ctx, "reporter-multi")
	require.NoError(t, err)
	assert.Len(t, results, count)
}

func TestKVReportStore_GetByReporter_IsolatesReporters(t *testing.T) {
	s, _ := newTestKVReportStore()
	ctx := context.Background()

	require.NoError(t, s.Store(ctx, testReport("r-A")))
	require.NoError(t, s.Store(ctx, testReport("r-B")))

	rA, err := s.GetByReporter(ctx, "r-A")
	require.NoError(t, err)
	assert.Len(t, rA, 1)

	rB, err := s.GetByReporter(ctx, "r-B")
	require.NoError(t, err)
	assert.Len(t, rB, 1)
}

func TestKVReportStore_GetByReporter_ScanError(t *testing.T) {
	fkv := store.NewFailingKVClient()
	fkv.ScanErr = errors.New("scan failure")
	s := NewKVReportStore(fkv)

	_, err := s.GetByReporter(context.Background(), "r")
	require.Error(t, err)
	assert.Equal(t, "scan failure", err.Error())
}

func TestKVReportStore_GetByReporter_UnmarshalError(t *testing.T) {
	// Write corrupt JSON directly to the reporter index prefix so that the
	// Scan callback triggers a json.Unmarshal failure.
	s, kv := newTestKVReportStore()
	ctx := context.Background()

	corruptKey := reportByReporterPrefix + "reporter-corrupt/rpt-9999"
	require.NoError(t, kv.Put(ctx, corruptKey, []byte("not-json{")))

	_, err := s.GetByReporter(ctx, "reporter-corrupt")
	require.Error(t, err)

	var rse *ReportStoreError
	require.True(t, errors.As(err, &rse))
	assert.Equal(t, "unmarshal", rse.Operation)
}

// --- Concurrent access ---

func TestKVReportStore_ConcurrentStore(t *testing.T) {
	s, _ := newTestKVReportStore()
	ctx := context.Background()

	const goroutines = 20
	const reportsEach = 5

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < reportsEach; i++ {
				r := testReport("concurrent-reporter")
				if err := s.Store(ctx, r); err != nil {
					t.Errorf("Store: %v", err)
				}
			}
		}()
	}
	wg.Wait()

	results, err := s.GetByReporter(ctx, "concurrent-reporter")
	require.NoError(t, err)
	assert.Len(t, results, goroutines*reportsEach)
}

// --- ReportStoreError ---

func TestReportStoreError_Error(t *testing.T) {
	tests := []struct {
		name      string
		operation string
		cause     string
		want      string
	}{
		{"put", "put", "connection refused", "report store put error: connection refused"},
		{"unmarshal", "unmarshal", "unexpected end of JSON", "report store unmarshal error: unexpected end of JSON"},
		{"put-index", "put-index", "timeout", "report store put-index error: timeout"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &ReportStoreError{Operation: tt.operation, Cause: errors.New(tt.cause)}
			assert.Equal(t, tt.want, e.Error())
		})
	}
}

func TestReportStoreError_Unwrap(t *testing.T) {
	cause := errors.New("root cause")
	e := &ReportStoreError{Operation: "get", Cause: cause}
	assert.Equal(t, cause, e.Unwrap())
}

func TestReportStoreError_ErrorsAs(t *testing.T) {
	cause := errors.New("wrapped")
	e := &ReportStoreError{Operation: "put", Cause: cause}
	var target *ReportStoreError
	require.True(t, errors.As(e, &target))
	assert.Equal(t, "put", target.Operation)
}

func TestReportStoreError_ErrorsIs(t *testing.T) {
	sentinel := errors.New("sentinel")
	e := &ReportStoreError{Operation: "put", Cause: sentinel}
	assert.True(t, errors.Is(e, sentinel))
}

// --- uitoa ---

func TestUitoa(t *testing.T) {
	tests := []struct {
		input uint64
		want  string
	}{
		{0, "0"},
		{1, "1"},
		{9, "9"},
		{10, "10"},
		{42, "42"},
		{100, "100"},
		{12345678, "12345678"},
		{^uint64(0), "18446744073709551615"}, // max uint64
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			assert.Equal(t, tt.want, uitoa(tt.input))
		})
	}
}

// --- Interface compliance ---

func TestKVReportStore_ImplementsReportStore(t *testing.T) {
	var _ ReportStore = (*KVReportStore)(nil)
}

// --- countingKVClient is a test-local KVClient that fails Put after N calls. ---

type countingKVClient struct {
	delegate   store.KVClient
	putCalls   int
	failAfter  int
	putFailErr error
}

func (c *countingKVClient) Put(ctx context.Context, key string, value []byte) error {
	c.putCalls++
	if c.putCalls > c.failAfter {
		return c.putFailErr
	}
	return c.delegate.Put(ctx, key, value)
}

func (c *countingKVClient) Get(ctx context.Context, key string) ([]byte, error) {
	return c.delegate.Get(ctx, key)
}

func (c *countingKVClient) Delete(ctx context.Context, key string) error {
	return c.delegate.Delete(ctx, key)
}

func (c *countingKVClient) DeleteIfPresent(ctx context.Context, key string) (bool, error) {
	return c.delegate.DeleteIfPresent(ctx, key)
}

func (c *countingKVClient) List(ctx context.Context, prefix string) ([]string, error) {
	return c.delegate.List(ctx, prefix)
}

func (c *countingKVClient) Scan(ctx context.Context, prefix string, fn func(string, []byte) error) error {
	return c.delegate.Scan(ctx, prefix, fn)
}

func (c *countingKVClient) Exists(ctx context.Context, key string) (bool, error) {
	return c.delegate.Exists(ctx, key)
}
