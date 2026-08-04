package store

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewFailingKVClient(t *testing.T) {
	fkv := NewFailingKVClient()
	require.NotNil(t, fkv)
	require.NotNil(t, fkv.Delegate)
}

func TestNewFailingKVClient_DefaultsToNoErrors(t *testing.T) {
	fkv := NewFailingKVClient()
	assert.Nil(t, fkv.PutErr)
	assert.Nil(t, fkv.GetErr)
	assert.Nil(t, fkv.DeleteErr)
	assert.Nil(t, fkv.ListErr)
	assert.Nil(t, fkv.ScanErr)
	assert.Nil(t, fkv.ExistsErr)
}

func TestFailingKVClient_Put_DelegatesToMemory(t *testing.T) {
	fkv := NewFailingKVClient()
	ctx := context.Background()

	require.NoError(t, fkv.Put(ctx, "k", []byte("v")))

	got, err := fkv.Get(ctx, "k")
	require.NoError(t, err)
	assert.Equal(t, []byte("v"), got)
}

func TestFailingKVClient_Put_ReturnsError(t *testing.T) {
	fkv := NewFailingKVClient()
	fkv.PutErr = errors.New("put fail")

	err := fkv.Put(context.Background(), "k", []byte("v"))
	require.Error(t, err)
	assert.Equal(t, "put fail", err.Error())
}

func TestFailingKVClient_Get_ReturnsError(t *testing.T) {
	fkv := NewFailingKVClient()
	fkv.GetErr = errors.New("get fail")

	_, err := fkv.Get(context.Background(), "k")
	require.Error(t, err)
	assert.Equal(t, "get fail", err.Error())
}

func TestFailingKVClient_Delete_DelegatesToMemory(t *testing.T) {
	fkv := NewFailingKVClient()
	ctx := context.Background()

	require.NoError(t, fkv.Put(ctx, "k", []byte("v")))
	require.NoError(t, fkv.Delete(ctx, "k"))

	exists, err := fkv.Exists(ctx, "k")
	require.NoError(t, err)
	assert.False(t, exists)
}

func TestFailingKVClient_Delete_ReturnsError(t *testing.T) {
	fkv := NewFailingKVClient()
	fkv.DeleteErr = errors.New("del fail")

	err := fkv.Delete(context.Background(), "k")
	require.Error(t, err)
	assert.Equal(t, "del fail", err.Error())
}

func TestFailingKVClient_List_DelegatesToMemory(t *testing.T) {
	fkv := NewFailingKVClient()
	ctx := context.Background()

	require.NoError(t, fkv.Put(ctx, "pre/a", []byte("1")))
	require.NoError(t, fkv.Put(ctx, "pre/b", []byte("2")))

	keys, err := fkv.List(ctx, "pre/")
	require.NoError(t, err)
	assert.Equal(t, []string{"pre/a", "pre/b"}, keys)
}

func TestFailingKVClient_List_ReturnsError(t *testing.T) {
	fkv := NewFailingKVClient()
	fkv.ListErr = errors.New("list fail")

	_, err := fkv.List(context.Background(), "pre/")
	require.Error(t, err)
	assert.Equal(t, "list fail", err.Error())
}

func TestFailingKVClient_Scan_DelegatesToMemory(t *testing.T) {
	fkv := NewFailingKVClient()
	ctx := context.Background()

	require.NoError(t, fkv.Put(ctx, "ns/a", []byte("1")))

	var found bool
	err := fkv.Scan(ctx, "ns/", func(key string, value []byte) error {
		found = true
		return nil
	})
	require.NoError(t, err)
	assert.True(t, found)
}

func TestFailingKVClient_Scan_ReturnsError(t *testing.T) {
	fkv := NewFailingKVClient()
	fkv.ScanErr = errors.New("scan fail")

	err := fkv.Scan(context.Background(), "ns/", func(key string, value []byte) error {
		return nil
	})
	require.Error(t, err)
	assert.Equal(t, "scan fail", err.Error())
}

func TestFailingKVClient_Exists_DelegatesToMemory(t *testing.T) {
	fkv := NewFailingKVClient()
	ctx := context.Background()

	require.NoError(t, fkv.Put(ctx, "k", []byte("v")))

	exists, err := fkv.Exists(ctx, "k")
	require.NoError(t, err)
	assert.True(t, exists)
}

func TestFailingKVClient_Exists_ReturnsError(t *testing.T) {
	fkv := NewFailingKVClient()
	fkv.ExistsErr = errors.New("exists fail")

	_, err := fkv.Exists(context.Background(), "k")
	require.Error(t, err)
	assert.Equal(t, "exists fail", err.Error())
}

func TestFailingKVClient_ImplementsKVClient(t *testing.T) {
	var _ KVClient = &FailingKVClient{}
}

func TestFailingKVClient_DeleteIfPresent_DelegatesToMemory_Exists(t *testing.T) {
	fkv := NewFailingKVClient()
	ctx := context.Background()

	require.NoError(t, fkv.Put(ctx, "k", []byte("v")))

	deleted, err := fkv.DeleteIfPresent(ctx, "k")
	require.NoError(t, err)
	assert.True(t, deleted)

	exists, err := fkv.Exists(ctx, "k")
	require.NoError(t, err)
	assert.False(t, exists)
}

func TestFailingKVClient_DeleteIfPresent_DelegatesToMemory_Absent(t *testing.T) {
	fkv := NewFailingKVClient()
	ctx := context.Background()

	deleted, err := fkv.DeleteIfPresent(ctx, "absent-key")
	require.NoError(t, err)
	assert.False(t, deleted)
}

func TestFailingKVClient_DeleteIfPresent_ReturnsError(t *testing.T) {
	fkv := NewFailingKVClient()
	fkv.DeleteErr = errors.New("delete-if-present fail")

	deleted, err := fkv.DeleteIfPresent(context.Background(), "k")
	require.Error(t, err)
	assert.False(t, deleted)
	assert.Equal(t, "delete-if-present fail", err.Error())
}
