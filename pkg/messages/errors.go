package messages

import (
	"fmt"
	"strconv"
)

// InvalidArgumentError indicates a required argument was missing or invalid.
type InvalidArgumentError struct {
	Field   string
	Message string
}

func (e *InvalidArgumentError) Error() string {
	return "invalid argument: " + e.Field + ": " + e.Message
}

// MessageNotFoundError indicates the requested message does not exist.
type MessageNotFoundError struct {
	ServerGUID string
}

func (e *MessageNotFoundError) Error() string {
	return "message not found: " + e.ServerGUID
}

// QueueError wraps an error from a CacheQueue operation. Key is the optional
// GUID or other lookup token associated with the failing operation; when
// empty, the message format omits the key segment.
type QueueError struct {
	Op    string
	Key   string
	Cause error
}

func (e *QueueError) Error() string {
	if e.Key != "" {
		return "messages/queue: " + e.Op + " " + e.Key + ": " + e.Cause.Error()
	}
	return "messages/queue: " + e.Op + ": " + e.Cause.Error()
}

// Unwrap returns the underlying cause so errors.Is/As can traverse the chain.
func (e *QueueError) Unwrap() error { return e.Cause }

// MRMCacheError wraps an error from an MRMCache operation. It is used by
// MRMCache methods in mrm.go. The message format is "mrm {Op}: {cause}".
type MRMCacheError struct {
	Op    string
	Cause error
}

func (e *MRMCacheError) Error() string {
	return "mrm " + e.Op + ": " + e.Cause.Error()
}

// Unwrap returns the underlying cause so errors.Is/As can traverse the chain.
func (e *MRMCacheError) Unwrap() error { return e.Cause }

// MRMUnexpectedResultTypeError is returned by MRMCache.RemoveRecipientView
// when the Lua script evaluation returns a value of an unrecognised Go type.
type MRMUnexpectedResultTypeError struct {
	// Result is the value returned by the cache Eval call.
	Result interface{}
}

func (e *MRMUnexpectedResultTypeError) Error() string {
	return fmt.Sprintf("mrm remove: unexpected result type %T", e.Result)
}

// MRMSendError wraps an error from SendMRMBinary. The message format is
// "mrm: {Op}: {cause}" for simple cases, and
// "mrm: {Op} {UUID}: {cause}" / "mrm: {Op} {UUID}/{Device}: {cause}" when
// recipient context is available. Device==0 means no device is associated.
type MRMSendError struct {
	Op     string
	UUID   string
	Device uint64
	Cause  error
}

func (e *MRMSendError) Error() string {
	s := "mrm: " + e.Op
	if e.UUID != "" && e.Device != 0 {
		s += " " + e.UUID + "/" + strconv.FormatUint(e.Device, 10)
	} else if e.UUID != "" {
		s += " " + e.UUID
	}
	if e.Cause != nil {
		s += ": " + e.Cause.Error()
	}
	return s
}

// Unwrap returns the underlying cause so errors.Is/As can traverse the chain.
func (e *MRMSendError) Unwrap() error { return e.Cause }

// PersisterError wraps an error from a MessagePersister operation. Key is the
// optional ServerGUID or other identifier; when empty, the message format
// omits the key segment.
type PersisterError struct {
	Op    string
	Key   string
	Cause error
}

func (e *PersisterError) Error() string {
	if e.Key != "" {
		return e.Op + " " + e.Key + ": " + e.Cause.Error()
	}
	return e.Op + ": " + e.Cause.Error()
}

// Unwrap returns the underlying cause so errors.Is/As can traverse the chain.
func (e *PersisterError) Unwrap() error { return e.Cause }
