package backups_test

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"

	"github.com/jeremyhahn/go-signal/pkg/backups"
)

// fakeBlobStore is an in-memory backups.BlobStore for testing the Manager
// without spinning up real CDN infrastructure. It records every Copy,
// Upload, and Delete call so tests can assert behavior, and supports
// closures to inject failures for specific keys.
type fakeBlobStore struct {
	mu             sync.Mutex
	cdn            int
	objects        map[string][]byte
	uploadCalls    []string
	deleteCalls    []string
	copyCalls      []copyCall
	headerPrefixes []string
	copyFailFor    map[string]error
}

type copyCall struct {
	SourceCDN int
	SourceKey string
	DestPath  string
	Params    backups.MediaEncryptionParameters
}

func newFakeBlobStore() *fakeBlobStore {
	return &fakeBlobStore{
		cdn:         3,
		objects:     make(map[string][]byte),
		copyFailFor: make(map[string]error),
	}
}

func (f *fakeBlobStore) CDNNumber() int { return f.cdn }

func (f *fakeBlobStore) GenerateUpload(_ context.Context, key string) (*backups.UploadDescriptor, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.uploadCalls = append(f.uploadCalls, key)
	return &backups.UploadDescriptor{
		CDN:                  f.cdn,
		Key:                  key,
		Headers:              map[string]string{"X-Goog-Resumable": "start"},
		SignedUploadLocation: "https://cdn.example/" + key,
	}, nil
}

func (f *fakeBlobStore) ReadHeaders(_ context.Context, prefix string) (map[string]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.headerPrefixes = append(f.headerPrefixes, prefix)
	return map[string]string{"Authorization": "Bearer test-token"}, nil
}

func (f *fakeBlobStore) Copy(
	_ context.Context,
	sourceCDN int,
	sourceKey string,
	_ int,
	params backups.MediaEncryptionParameters,
	destPath string,
) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err, ok := f.copyFailFor[sourceKey]; ok {
		return err
	}
	f.copyCalls = append(f.copyCalls, copyCall{
		SourceCDN: sourceCDN, SourceKey: sourceKey, DestPath: destPath, Params: params,
	})
	// Simulate writing the destination by storing a placeholder payload
	// whose length matches the encrypted output size for a 100-byte source —
	// tests that need real sizes inject their own via objects[].
	f.objects[destPath] = make([]byte, 128)
	return nil
}

func (f *fakeBlobStore) Delete(_ context.Context, path string) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deleteCalls = append(f.deleteCalls, path)
	data, ok := f.objects[path]
	if !ok {
		return 0, nil
	}
	delete(f.objects, path)
	return int64(len(data)), nil
}

func (f *fakeBlobStore) List(
	_ context.Context,
	prefix string,
	cursor *string,
	limit int,
) (*backups.BlobListResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var keys []string
	for k := range f.objects {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, strings.TrimPrefix(k, prefix))
		}
	}
	sort.Strings(keys)
	start := 0
	if cursor != nil {
		for i, k := range keys {
			if k > *cursor {
				start = i
				break
			}
		}
	}
	end := len(keys)
	if limit > 0 && start+limit < end {
		end = start + limit
	}
	out := &backups.BlobListResult{}
	for _, k := range keys[start:end] {
		out.Objects = append(out.Objects, backups.BlobListEntry{
			Key:    k,
			Length: int64(len(f.objects[prefix+k])),
		})
	}
	if end < len(keys) {
		next := keys[end-1]
		out.Cursor = &next
	}
	return out, nil
}

func (f *fakeBlobStore) CalculateBytesUsed(_ context.Context, prefix string) (backups.UsageInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var info backups.UsageInfo
	for k, v := range f.objects {
		if strings.HasPrefix(k, prefix) {
			info.NumObjects++
			info.BytesUsed += int64(len(v))
		}
	}
	return info, nil
}

// failingCopy is a sentinel error fake tests inject through copyFailFor
// to force the manager's classifyCopyError into the "unexpected" branch.
var errFakeBlobCopy = errors.New("fake blob copy: unrecoverable")
