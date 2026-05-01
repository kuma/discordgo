package discordgo

import "testing"

func TestVoiceConnection_SSRCMapping(t *testing.T) {
	v := &VoiceConnection{}

	// Empty before any updates.
	if _, ok := v.lookupUserBySSRC(123); ok {
		t.Error("expected no mapping for unknown SSRC")
	}

	// Set and look up.
	v.setUserForSSRC(123, "111111111111111111")
	got, ok := v.lookupUserBySSRC(123)
	if !ok || got != "111111111111111111" {
		t.Errorf("after set: got (%q, %t), want (%q, true)", got, ok, "111111111111111111")
	}

	// Overwrite (Discord reassigns SSRCs across reconnects).
	v.setUserForSSRC(123, "222222222222222222")
	got, ok = v.lookupUserBySSRC(123)
	if !ok || got != "222222222222222222" {
		t.Errorf("after overwrite: got (%q, %t), want (%q, true)", got, ok, "222222222222222222")
	}

	// Distinct SSRCs are independent.
	v.setUserForSSRC(456, "333333333333333333")
	if got, ok := v.lookupUserBySSRC(456); !ok || got != "333333333333333333" {
		t.Errorf("second SSRC: got (%q, %t)", got, ok)
	}
	if got, ok := v.lookupUserBySSRC(123); !ok || got != "222222222222222222" {
		t.Errorf("first SSRC overwritten by second: got (%q, %t)", got, ok)
	}
}
