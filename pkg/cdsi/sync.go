package cdsi

import (
	"context"
	"errors"
	"io"

	dirpb "github.com/jeremyhahn/go-signal/pkg/api/grpc/genproto/directory"
)

// LoadFromSignald drains signald's DirectoryService.ListEntries stream
// and atomically replaces the contents of dir. Called at cmd/cdsi
// startup; future deployments may also call it periodically to refresh
// from a stable replica.
func LoadFromSignald(ctx context.Context, client dirpb.DirectoryServiceClient, dir *MemoryDirectory, pageSize uint32) error {
	if client == nil {
		return errors.New("cdsi: directory client is required")
	}
	if dir == nil {
		return errors.New("cdsi: directory is required")
	}
	stream, err := client.ListEntries(ctx, &dirpb.ListEntriesRequest{PageSize: pageSize})
	if err != nil {
		return err
	}
	var entries []Entry
	for {
		msg, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		entry := Entry{E164: msg.GetE164()}
		copy(entry.ACI[:], msg.GetAci())
		copy(entry.PNI[:], msg.GetPni())
		copy(entry.AccessKey[:], msg.GetAccessKey())
		entries = append(entries, entry)
	}
	return dir.Replace(ctx, entries)
}
