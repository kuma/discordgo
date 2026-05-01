package discordgo

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// activeSessionForTest builds a DAVESession with a synthetic exporter
// secret installed, bypassing the real MLS Welcome flow. The userID is
// the session's own identity (used by EncryptFrame); decrypt calls supply
// the sender's userID separately.
func activeSessionForTest(t *testing.T, userID string, exporterSecret []byte) *DAVESession {
	t.Helper()
	d := NewDAVESession(userID)
	d.exporterSecret = exporterSecret
	d.epoch = 1
	if err := d.deriveSenderKeyLocked(); err != nil {
		t.Fatalf("deriveSenderKeyLocked: %v", err)
	}
	d.active = true
	return d
}

// TestDecryptFrame_CrossSession verifies that a frame encrypted by session
// A using A's own sender key can be decrypted by session B treating A as a
// remote sender, given a shared exporter secret (i.e. they are in the
// same MLS group).
func TestDecryptFrame_CrossSession(t *testing.T) {
	exporter := make([]byte, 32)
	if _, err := rand.Read(exporter); err != nil {
		t.Fatalf("random exporter: %v", err)
	}

	const (
		alice = "111111111111111111"
		bob   = "222222222222222222"
	)

	sessionA := activeSessionForTest(t, alice, exporter)
	sessionB := activeSessionForTest(t, bob, exporter)

	payload := []byte("an opus-shaped voice frame")
	encrypted, err := sessionA.EncryptFrame(payload)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	got, err := sessionB.DecryptFrame(alice, encrypted)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("payload mismatch: got %x, want %x", got, payload)
	}
}

// TestDecryptFrame_MultipleSenders confirms that two different senders in
// the same group derive distinct per-sender keys. A frame from Alice cannot
// be decrypted as if it came from Carol — the resulting bytes will not
// match the original payload (no auth = garbage, not error).
func TestDecryptFrame_MultipleSenders(t *testing.T) {
	exporter := make([]byte, 32)
	rand.Read(exporter)

	const (
		alice = "111111111111111111"
		bob   = "222222222222222222"
		carol = "333333333333333333"
	)

	sessionA := activeSessionForTest(t, alice, exporter)
	sessionB := activeSessionForTest(t, bob, exporter)

	payload := []byte("alice speaks")
	encrypted, _ := sessionA.EncryptFrame(payload)

	wrong, err := sessionB.DecryptFrame(carol, encrypted)
	if err != nil {
		t.Fatalf("decrypt with wrong sender returned error (expected garbage): %v", err)
	}
	if bytes.Equal(wrong, payload) {
		t.Error("decrypt with wrong sender produced original plaintext")
	}

	right, err := sessionB.DecryptFrame(alice, encrypted)
	if err != nil {
		t.Fatalf("decrypt with correct sender: %v", err)
	}
	if !bytes.Equal(right, payload) {
		t.Errorf("correct-sender decrypt mismatch: got %x, want %x", right, payload)
	}
}

// TestDecryptFrame_GenerationRollover verifies that frames spanning a
// generation boundary (nonce MSB change) decrypt correctly on the receive
// side. The encrypt side's senderNonce is bumped past 2^24 to force the
// ratchet to advance.
func TestDecryptFrame_GenerationRollover(t *testing.T) {
	exporter := make([]byte, 32)
	rand.Read(exporter)

	const sender = "111111111111111111"
	encSession := activeSessionForTest(t, sender, exporter)
	decSession := activeSessionForTest(t, "999999999999999999", exporter)

	// Encrypt a frame in generation 0.
	payloadGen0 := []byte("frame in generation 0")
	frameGen0, err := encSession.EncryptFrame(payloadGen0)
	if err != nil {
		t.Fatalf("encrypt gen0: %v", err)
	}

	// Force encrypt session to the boundary so the next frame triggers gen1.
	encSession.mu.Lock()
	encSession.senderNonce = (1 << 24) - 1
	encSession.mu.Unlock()

	payloadGen1 := []byte("frame in generation 1")
	frameGen1, err := encSession.EncryptFrame(payloadGen1)
	if err != nil {
		t.Fatalf("encrypt gen1: %v", err)
	}

	// In-order receive: gen0 then gen1.
	gotGen0, err := decSession.DecryptFrame(sender, frameGen0)
	if err != nil || !bytes.Equal(gotGen0, payloadGen0) {
		t.Fatalf("gen0 in-order: err=%v, got=%x", err, gotGen0)
	}
	gotGen1, err := decSession.DecryptFrame(sender, frameGen1)
	if err != nil || !bytes.Equal(gotGen1, payloadGen1) {
		t.Fatalf("gen1 in-order: err=%v, got=%x", err, gotGen1)
	}
}

// TestDecryptFrame_OutOfOrderRetainsPrevGen confirms that after a
// generation advance, late frames from the previous generation still
// decrypt thanks to the two-slot retention window.
func TestDecryptFrame_OutOfOrderRetainsPrevGen(t *testing.T) {
	exporter := make([]byte, 32)
	rand.Read(exporter)

	const sender = "111111111111111111"
	encSession := activeSessionForTest(t, sender, exporter)
	decSession := activeSessionForTest(t, "999999999999999999", exporter)

	// Generation 0 frame.
	payload0 := []byte("late gen0 frame")
	frame0, _ := encSession.EncryptFrame(payload0)

	// Force gen1 boundary and emit a gen1 frame.
	encSession.mu.Lock()
	encSession.senderNonce = (1 << 24) - 1
	encSession.mu.Unlock()
	payload1 := []byte("on-time gen1 frame")
	frame1, _ := encSession.EncryptFrame(payload1)

	// Receive gen1 first (forward jump).
	got1, err := decSession.DecryptFrame(sender, frame1)
	if err != nil || !bytes.Equal(got1, payload1) {
		t.Fatalf("gen1 first: err=%v got=%x", err, got1)
	}

	// Now receive late gen0; should still decrypt from the retained slot.
	got0, err := decSession.DecryptFrame(sender, frame0)
	if err != nil {
		t.Fatalf("late gen0: %v", err)
	}
	if !bytes.Equal(got0, payload0) {
		t.Errorf("late gen0 mismatch: got %x, want %x", got0, payload0)
	}
}

// TestDecryptFrame_RejectsInactive ensures DecryptFrame errors out when
// the session has not yet completed Welcome+ExecuteTransition.
func TestDecryptFrame_RejectsInactive(t *testing.T) {
	d := NewDAVESession("111111111111111111")
	if _, err := d.DecryptFrame("222222222222222222", []byte{0xFA, 0xFA}); err == nil {
		t.Error("expected error on inactive session, got nil")
	}
}

// TestDecryptFrame_RemoteSenderResetOnEpoch verifies that remoteSenders
// state is cleared when HandlePrepareEpoch fires. After reset, decrypting
// pre-reset frames should fail because the exporter secret changed.
func TestDecryptFrame_RemoteSenderResetOnEpoch(t *testing.T) {
	exporter := make([]byte, 32)
	rand.Read(exporter)
	const alice = "111111111111111111"
	const bob = "222222222222222222"

	sessA := activeSessionForTest(t, alice, exporter)
	sessB := activeSessionForTest(t, bob, exporter)

	payload := []byte("pre-epoch frame")
	frame, _ := sessA.EncryptFrame(payload)

	if got, err := sessB.DecryptFrame(alice, frame); err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("pre-epoch decrypt: err=%v got=%x", err, got)
	}

	// Trigger an epoch transition. The remoteSenders map should be cleared
	// and exporterSecret zeroed; subsequent decrypts must fail until a new
	// Welcome installs a fresh secret.
	if _, err := sessB.HandlePrepareEpoch(2, 1); err != nil {
		t.Fatalf("HandlePrepareEpoch: %v", err)
	}

	if _, err := sessB.DecryptFrame(alice, frame); err == nil {
		t.Error("expected error after epoch reset, got nil")
	}
}
