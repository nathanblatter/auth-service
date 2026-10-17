package ratelimit

import (
	"context"
	"testing"
	"time"

	"github.com/nathanblatter/squawk/internal/store"
)

func TestLimiter(t *testing.T) {
	mem := store.NewMemory()
	l := New(mem)
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	l.Now = func() time.Time { return now }
	ctx := context.Background()
	p := Policy{Limit: 3, Window: 10 * time.Minute}

	for i := 0; i < 3; i++ {
		if !l.Allow(ctx, p, "k") {
			t.Fatalf("blocked after %d failures", i)
		}
		l.Fail(ctx, p, "k")
	}
	if l.Allow(ctx, p, "k") {
		t.Fatal("allowed at the limit")
	}
	if !l.Allow(ctx, p, "other") {
		t.Fatal("keys must be independent")
	}
	now = now.Add(11 * time.Minute)
	if !l.Allow(ctx, p, "k") {
		t.Fatal("window did not reset")
	}
}
