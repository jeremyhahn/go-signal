package performance

import (
	"context"
	"testing"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/auth"
	"github.com/jeremyhahn/go-signal/pkg/limits"
	"github.com/jeremyhahn/go-signal/pkg/spam"
)

// BenchmarkTokenBucketLimiter_Allow benchmarks the hot path for rate limiting
// under parallel load with distinct keys to avoid single-bucket contention.
func BenchmarkTokenBucketLimiter_Allow(b *testing.B) {
	cfg := limits.DefaultConfig()
	l := limits.NewTokenBucketLimiter(cfg.Messages)
	defer l.Stop()
	ctx := context.Background()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			// Rotate across 256 distinct keys to exercise the sync.Map hot path
			// without saturating any single bucket.
			key := "bench-key-" + string(rune('A'+i%26)) + string(rune('0'+i%10))
			_ = l.Allow(ctx, key)
			i++
		}
	})
}

// BenchmarkTokenBucketLimiter_Allow_SingleKey benchmarks the single-key
// contention path, which exercises the CAS loop under concurrent access.
func BenchmarkTokenBucketLimiter_Allow_SingleKey(b *testing.B) {
	cfg := limits.DefaultConfig()
	l := limits.NewTokenBucketLimiter(cfg.Messages)
	defer l.Stop()
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = l.Allow(ctx, "single-key")
	}
}

// BenchmarkTokenBucketLimiter_AllowN benchmarks consuming multiple tokens in
// a single call, exercising the cost-scaled CAS path.
func BenchmarkTokenBucketLimiter_AllowN(b *testing.B) {
	cfg := limits.DefaultConfig()
	l := limits.NewTokenBucketLimiter(cfg.Messages)
	defer l.Stop()
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = l.AllowN(ctx, "allown-key", 5)
	}
}

// BenchmarkSaltedTokenHash_NewAndVerify benchmarks the full round-trip of
// deriving a salted HKDF-SHA256 hash and immediately verifying it.
func BenchmarkSaltedTokenHash_NewAndVerify(b *testing.B) {
	for i := 0; i < b.N; i++ {
		hash, err := auth.NewSaltedTokenHash("benchmark-token-value")
		if err != nil {
			b.Fatal(err)
		}
		hash.Verify([]byte("benchmark-token-value"))
	}
}

// BenchmarkSaltedTokenHash_Verify benchmarks the HKDF-SHA256 verification
// path in isolation, reusing a pre-computed hash struct.
func BenchmarkSaltedTokenHash_Verify(b *testing.B) {
	hash, err := auth.NewSaltedTokenHash("benchmark-token-value")
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hash.Verify([]byte("benchmark-token-value"))
	}
}

// BenchmarkSaltedTokenHash_New benchmarks only the hash derivation step
// (random salt generation + HKDF expansion).
func BenchmarkSaltedTokenHash_New(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := auth.NewSaltedTokenHash("benchmark-token-value")
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkRateLimitChecker_Check benchmarks the spam rate-limit hot path
// under parallel load with distinct senders to minimise write-lock contention.
func BenchmarkRateLimitChecker_Check(b *testing.B) {
	checker := spam.NewRateLimitChecker(spam.RateLimitConfig{
		Threshold: 1000,
		Window:    time.Minute,
	})
	defer checker.Stop()
	ctx := context.Background()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			checkCtx := &spam.CheckContext{
				SenderUUID: "sender-" + string(rune('A'+i%26)),
			}
			_, _ = checker.Check(ctx, checkCtx)
			i++
		}
	})
}

// BenchmarkRateLimitChecker_Check_SingleSender benchmarks the single-sender
// path, which exercises the atomic increment loop without map lookups after
// the first call.
func BenchmarkRateLimitChecker_Check_SingleSender(b *testing.B) {
	checker := spam.NewRateLimitChecker(spam.RateLimitConfig{
		Threshold: 1000000,
		Window:    time.Minute,
	})
	defer checker.Stop()
	ctx := context.Background()

	checkCtx := &spam.CheckContext{
		SenderUUID: "single-sender",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = checker.Check(ctx, checkCtx)
	}
}
