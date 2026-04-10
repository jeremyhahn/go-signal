package entities

import "github.com/jeremyhahn/go-qrdb/pkg/index"

// JobStatus identifies the state of a persistent job.
const (
	JobStatusPending   = 0
	JobStatusRunning   = 1
	JobStatusCompleted = 2
	JobStatusFailed    = 3
)

// JobEntity represents a persistent async job in the job queue.
type JobEntity struct {
	ID          uint64 `json:"id"`
	QueueType   string `json:"queueType" index:"true"`
	Data        string `json:"data"`
	Status      int    `json:"status" index:"true"`
	Attempts    int    `json:"attempts"`
	MaxAttempts int    `json:"maxAttempts"`
	CreatedAt   int64  `json:"createdAt"`
	NextRunAt   int64  `json:"nextRunAt"`
	LastError   string `json:"lastError,omitempty"`
}

func (j *JobEntity) EntityID() uint64      { return j.ID }
func (j *JobEntity) SetEntityID(id uint64)  { j.ID = id }

// CompoundIndexes declares a compound index for efficient job queue queries.
func (j JobEntity) CompoundIndexes() []index.CompoundIndexDef {
	return []index.CompoundIndexDef{
		{Fields: []string{"QueueType", "Status", "NextRunAt"}},
	}
}
