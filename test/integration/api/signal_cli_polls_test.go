//go:build integration

package api

// signal-cli v0.13.12 does not include sendPoll* commands (sendPollCreate,
// sendPollVote, sendPollTerminate). Poll support was introduced in a later
// version. These tests are intentionally omitted until we upgrade signal-cli.
