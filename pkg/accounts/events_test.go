package accounts

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestDirectoryEventBus_PublishDeliversToSubscriber(t *testing.T) {
	b := NewDirectoryEventBus()
	sub, seq := b.Subscribe(context.Background(), 4)
	defer sub.Close()
	if seq != 0 {
		t.Errorf("initial seq = %d, want 0", seq)
	}

	b.Publish(DirectoryEventCreated, "uuid-a", &Account{UUID: "uuid-a", Number: "+1"})

	select {
	case e := <-sub.Events():
		if e.Seq != 1 || e.Kind != DirectoryEventCreated || e.UUID != "uuid-a" {
			t.Errorf("got %+v", e)
		}
		if e.Account == nil || e.Account.Number != "+1" {
			t.Errorf("account snapshot lost: %+v", e.Account)
		}
	case <-time.After(time.Second):
		t.Fatal("event not delivered")
	}
}

func TestDirectoryEventBus_AssignsMonotonicSeq(t *testing.T) {
	b := NewDirectoryEventBus()
	sub, _ := b.Subscribe(context.Background(), 8)
	defer sub.Close()

	for i := 0; i < 5; i++ {
		b.Publish(DirectoryEventUpdated, "uuid", &Account{UUID: "uuid"})
	}

	last := uint64(0)
	for i := 0; i < 5; i++ {
		select {
		case e := <-sub.Events():
			if e.Seq <= last {
				t.Errorf("seq not monotonic: %d after %d", e.Seq, last)
			}
			last = e.Seq
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for event")
		}
	}
	if last != 5 {
		t.Errorf("last seq = %d, want 5", last)
	}
}

func TestDirectoryEventBus_PublishWithoutSubscribersDoesNotBlock(t *testing.T) {
	b := NewDirectoryEventBus()
	done := make(chan struct{})
	go func() {
		for i := 0; i < 1000; i++ {
			b.Publish(DirectoryEventUpdated, "u", &Account{UUID: "u"})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Publish blocked without subscribers")
	}
	if b.LatestSeq() != 1000 {
		t.Errorf("LatestSeq = %d, want 1000", b.LatestSeq())
	}
}

func TestDirectoryEventBus_DeletedEventCarriesNilAccount(t *testing.T) {
	b := NewDirectoryEventBus()
	sub, _ := b.Subscribe(context.Background(), 4)
	defer sub.Close()

	b.Publish(DirectoryEventDeleted, "uuid-x", nil)
	e := <-sub.Events()
	if e.Kind != DirectoryEventDeleted || e.UUID != "uuid-x" {
		t.Errorf("got %+v", e)
	}
	if e.Account != nil {
		t.Errorf("delete event carries non-nil account: %+v", e.Account)
	}
}

func TestDirectoryEventBus_EmptyUUIDIsDropped(t *testing.T) {
	b := NewDirectoryEventBus()
	sub, _ := b.Subscribe(context.Background(), 4)
	defer sub.Close()

	b.Publish(DirectoryEventCreated, "", &Account{})
	select {
	case e := <-sub.Events():
		t.Errorf("event delivered despite empty UUID: %+v", e)
	case <-time.After(50 * time.Millisecond):
	}
	if b.LatestSeq() != 0 {
		t.Errorf("seq incremented for dropped event: %d", b.LatestSeq())
	}
}

func TestDirectoryEventBus_SlowSubscriberOverflowsAndDetaches(t *testing.T) {
	b := NewDirectoryEventBus()
	sub, _ := b.Subscribe(context.Background(), 1)

	// First Publish lands in the buffer, second overflows.
	b.Publish(DirectoryEventCreated, "a", &Account{UUID: "a"})
	b.Publish(DirectoryEventCreated, "b", &Account{UUID: "b"})

	select {
	case <-sub.Done():
	case <-time.After(time.Second):
		t.Fatal("slow subscriber not detached")
	}
	if !sub.Overflowed() {
		t.Error("Overflowed() = false; want true")
	}
}

func TestDirectoryEventBus_CloseDetachesSubscriber(t *testing.T) {
	b := NewDirectoryEventBus()
	sub, _ := b.Subscribe(context.Background(), 4)
	sub.Close()

	select {
	case <-sub.Done():
	case <-time.After(time.Second):
		t.Fatal("Close did not signal Done")
	}
	if sub.Overflowed() {
		t.Error("clean Close should not mark Overflowed")
	}

	b.Publish(DirectoryEventCreated, "u", &Account{UUID: "u"})
	if _, ok := <-sub.Events(); ok {
		t.Error("Events channel delivered after Close")
	}
}

func TestDirectoryEventBus_ContextCancelDetachesSubscriber(t *testing.T) {
	b := NewDirectoryEventBus()
	ctx, cancel := context.WithCancel(context.Background())
	sub, _ := b.Subscribe(ctx, 4)
	cancel()

	select {
	case <-sub.Done():
	case <-time.After(time.Second):
		t.Fatal("ctx cancel did not detach subscriber")
	}
}

func TestDirectoryEventBus_FanOutToManySubscribers(t *testing.T) {
	b := NewDirectoryEventBus()
	const N = 20
	subs := make([]*Subscription, N)
	for i := 0; i < N; i++ {
		subs[i], _ = b.Subscribe(context.Background(), 4)
	}

	b.Publish(DirectoryEventCreated, "u", &Account{UUID: "u"})

	var wg sync.WaitGroup
	wg.Add(N)
	for _, s := range subs {
		go func(s *Subscription) {
			defer wg.Done()
			select {
			case e := <-s.Events():
				if e.UUID != "u" {
					t.Errorf("got UUID %q", e.UUID)
				}
			case <-time.After(time.Second):
				t.Error("subscriber starved")
			}
		}(s)
	}
	wg.Wait()
	for _, s := range subs {
		s.Close()
	}
}

func TestDirectoryEventBus_SubscribeReturnsCurrentSeq(t *testing.T) {
	b := NewDirectoryEventBus()
	b.Publish(DirectoryEventCreated, "a", &Account{UUID: "a"})
	b.Publish(DirectoryEventCreated, "b", &Account{UUID: "b"})

	sub, asOf := b.Subscribe(context.Background(), 4)
	defer sub.Close()
	if asOf != 2 {
		t.Errorf("asOf = %d, want 2", asOf)
	}
	// Events published before subscribe are not replayed.
	select {
	case e := <-sub.Events():
		t.Errorf("got event before subscribe: %+v", e)
	case <-time.After(50 * time.Millisecond):
	}

	b.Publish(DirectoryEventUpdated, "a", &Account{UUID: "a"})
	e := <-sub.Events()
	if e.Seq != 3 {
		t.Errorf("post-subscribe seq = %d, want 3", e.Seq)
	}
}

func TestDirectoryEventBus_AccountSnapshotIsCopied(t *testing.T) {
	b := NewDirectoryEventBus()
	sub, _ := b.Subscribe(context.Background(), 4)
	defer sub.Close()

	acc := &Account{UUID: "u", Number: "+1"}
	b.Publish(DirectoryEventCreated, "u", acc)
	// Mutate after publish.
	acc.Number = "+2"

	e := <-sub.Events()
	if e.Account.Number != "+1" {
		t.Errorf("subscriber saw post-publish mutation: %q", e.Account.Number)
	}
}
