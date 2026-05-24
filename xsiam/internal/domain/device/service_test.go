package device_test

import (
	"context"
	"encoding/hex"
	"testing"
	"xsiam/internal/domain/device"
)

// GenerateEnrollmentToken is pure crypto — test via a nil-repo Service.
// Only GenerateEnrollmentToken works without real repos since all other
// methods delegate directly to devRepo/policyRepo/dsRepo/agentCtrl.

func TestGenerateEnrollmentToken_ReturnsHex64(t *testing.T) {
	svc := device.NewService(nil, nil, nil, nil, nil, nil)

	token, err := svc.GenerateEnrollmentToken(context.Background(), "t-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(token) != 64 {
		t.Errorf("expected 64-char hex token, got len=%d: %s", len(token), token)
	}
	if _, err := hex.DecodeString(token); err != nil {
		t.Errorf("token is not valid hex: %v", err)
	}
}

func TestGenerateEnrollmentToken_UniqueEachCall(t *testing.T) {
	svc := device.NewService(nil, nil, nil, nil, nil, nil)

	t1, _ := svc.GenerateEnrollmentToken(context.Background(), "t-1")
	t2, _ := svc.GenerateEnrollmentToken(context.Background(), "t-1")
	if t1 == t2 {
		t.Error("tokens should be unique across calls")
	}
}
