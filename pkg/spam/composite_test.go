package spam

import (
	"context"
	"errors"
	"testing"
)

// fixedChecker is a test SpamChecker that always returns a pre-configured result.
type fixedChecker struct {
	result SpamCheckResult
	err    error
}

func (f *fixedChecker) Check(_ context.Context, _ *CheckContext) (SpamCheckResult, error) {
	return f.result, f.err
}

func testCheckCtx() *CheckContext {
	return &CheckContext{
		SenderUUID:    "sender-uuid",
		RecipientUUID: "recipient-uuid",
	}
}

func TestCompositeChecker_EmptyReturnsAllow(t *testing.T) {
	c := NewCompositeChecker(nil)
	result, err := c.Check(context.Background(), testCheckCtx())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != SpamCheckAllow {
		t.Errorf("expected SpamCheckAllow, got %v", result)
	}
}

func TestCompositeChecker_AllAllowReturnsAllow(t *testing.T) {
	c := NewCompositeChecker([]SpamChecker{
		&fixedChecker{result: SpamCheckAllow},
		&fixedChecker{result: SpamCheckAllow},
		&fixedChecker{result: SpamCheckAllow},
	})
	result, err := c.Check(context.Background(), testCheckCtx())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != SpamCheckAllow {
		t.Errorf("expected SpamCheckAllow, got %v", result)
	}
}

func TestCompositeChecker_OneBlockReturnsBlock(t *testing.T) {
	c := NewCompositeChecker([]SpamChecker{
		&fixedChecker{result: SpamCheckAllow},
		&fixedChecker{result: SpamCheckBlock},
		&fixedChecker{result: SpamCheckAllow},
	})
	result, err := c.Check(context.Background(), testCheckCtx())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != SpamCheckBlock {
		t.Errorf("expected SpamCheckBlock, got %v", result)
	}
}

func TestCompositeChecker_ChallengeAndAllowReturnsChallenge(t *testing.T) {
	c := NewCompositeChecker([]SpamChecker{
		&fixedChecker{result: SpamCheckAllow},
		&fixedChecker{result: SpamCheckChallenge},
		&fixedChecker{result: SpamCheckAllow},
	})
	result, err := c.Check(context.Background(), testCheckCtx())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != SpamCheckChallenge {
		t.Errorf("expected SpamCheckChallenge, got %v", result)
	}
}

func TestCompositeChecker_BlockBeatsChallenge(t *testing.T) {
	c := NewCompositeChecker([]SpamChecker{
		&fixedChecker{result: SpamCheckChallenge},
		&fixedChecker{result: SpamCheckBlock},
	})
	result, err := c.Check(context.Background(), testCheckCtx())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != SpamCheckBlock {
		t.Errorf("expected SpamCheckBlock, got %v", result)
	}
}

func TestCompositeChecker_BlockShortCircuitsEvaluation(t *testing.T) {
	evaluated := false
	late := &callRecorder{
		result:  SpamCheckAllow,
		onCheck: func() { evaluated = true },
	}
	c := NewCompositeChecker([]SpamChecker{
		&fixedChecker{result: SpamCheckBlock},
		late,
	})
	result, _ := c.Check(context.Background(), testCheckCtx())
	if result != SpamCheckBlock {
		t.Errorf("expected SpamCheckBlock, got %v", result)
	}
	if evaluated {
		t.Error("expected checker after Block to be short-circuited, but it was evaluated")
	}
}

func TestCompositeChecker_PropagatesFirstError(t *testing.T) {
	sentinel := errors.New("checker error")
	c := NewCompositeChecker([]SpamChecker{
		&fixedChecker{result: SpamCheckAllow, err: sentinel},
		&fixedChecker{result: SpamCheckAllow},
	})
	_, err := c.Check(context.Background(), testCheckCtx())
	if !errors.Is(err, sentinel) {
		t.Errorf("expected sentinel error, got %v", err)
	}
}

func TestCompositeChecker_IsolatesInputSlice(t *testing.T) {
	checkers := []SpamChecker{
		&fixedChecker{result: SpamCheckAllow},
	}
	c := NewCompositeChecker(checkers)
	// Mutate the original slice — should not affect the composite.
	checkers[0] = &fixedChecker{result: SpamCheckBlock}
	result, _ := c.Check(context.Background(), testCheckCtx())
	if result != SpamCheckAllow {
		t.Errorf("expected SpamCheckAllow after input slice mutation, got %v", result)
	}
}

// callRecorder is a test SpamChecker that invokes onCheck when Check is called.
type callRecorder struct {
	result  SpamCheckResult
	onCheck func()
}

func (r *callRecorder) Check(_ context.Context, _ *CheckContext) (SpamCheckResult, error) {
	if r.onCheck != nil {
		r.onCheck()
	}
	return r.result, nil
}
