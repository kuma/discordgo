package discordgo

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestDecodeULEB128(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		want    uint32
		wantN   int
		wantErr bool
	}{
		{name: "zero", input: []byte{0x00}, want: 0, wantN: 1},
		{name: "one byte", input: []byte{0x7F}, want: 127, wantN: 1},
		{name: "two bytes", input: []byte{0x80, 0x01}, want: 128, wantN: 2},
		{name: "max uint32", input: []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x0F}, want: 0xFFFFFFFF, wantN: 5},
		{name: "trailing data ignored", input: []byte{0x05, 0xAA, 0xBB}, want: 5, wantN: 1},
		{name: "unterminated", input: []byte{0x80, 0x80, 0x80}, wantErr: true},
		{name: "overflows uint32", input: []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, wantErr: true},
		{name: "too long", input: []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x01}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotN, err := decodeULEB128(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("decodeULEB128 err = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if got != tt.want || gotN != tt.wantN {
				t.Errorf("decodeULEB128 = (%d, %d), want (%d, %d)", got, gotN, tt.want, tt.wantN)
			}
		})
	}
}

func TestEncodeDecodeULEB128Roundtrip(t *testing.T) {
	values := []uint32{0, 1, 63, 127, 128, 16383, 16384, 2097151, 2097152, 1<<24 - 1, 1 << 24, 1 << 28, 0xFFFFFFFF}
	for _, v := range values {
		encoded := encodeULEB128(v)
		got, n, err := decodeULEB128(encoded)
		if err != nil {
			t.Fatalf("decode %d: %v", v, err)
		}
		if got != v || n != len(encoded) {
			t.Errorf("roundtrip %d: got (%d, %d), want (%d, %d)", v, got, n, v, len(encoded))
		}
	}
}

// TestSecureFrameRoundtrip verifies that decryptSecureFrame inverts
// encryptSecureFrame for varying nonces and payload sizes. AES-CTR
// decryption is correct iff the keystream matches encrypt's GCM keystream,
// since GCM-CTR encryption is identical bytes — only tag verification
// differs.
func TestSecureFrameRoundtrip(t *testing.T) {
	key := make([]byte, daveKeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("random key: %v", err)
	}

	encCipher, err := newDAVECipher(key)
	if err != nil {
		t.Fatalf("encrypt cipher: %v", err)
	}
	decBlock, err := newDAVEDecryptCipher(key)
	if err != nil {
		t.Fatalf("decrypt block: %v", err)
	}

	cases := []struct {
		name    string
		nonce   uint32
		payload []byte
	}{
		{name: "nonce=1 small", nonce: 1, payload: []byte("hello opus")},
		{name: "nonce=127 (1B ULEB)", nonce: 127, payload: bytes.Repeat([]byte{0xAB}, 80)},
		{name: "nonce=128 (2B ULEB)", nonce: 128, payload: bytes.Repeat([]byte{0xCD}, 240)},
		{name: "nonce=16384 (3B ULEB)", nonce: 16384, payload: bytes.Repeat([]byte{0xEF}, 960)},
		{name: "nonce=2^24 (gen rollover)", nonce: 1 << 24, payload: bytes.Repeat([]byte{0x12}, 480)},
		{name: "nonce=max uint32", nonce: 0xFFFFFFFF, payload: bytes.Repeat([]byte{0x34}, 100)},
		{name: "empty payload", nonce: 5, payload: []byte{}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			frame := encryptSecureFrame(encCipher, tc.nonce, tc.payload)
			plain, gotNonce, err := decryptSecureFrame(decBlock, frame)
			if err != nil {
				t.Fatalf("decrypt failed: %v", err)
			}
			if gotNonce != tc.nonce {
				t.Errorf("nonce: got %d, want %d", gotNonce, tc.nonce)
			}
			if !bytes.Equal(plain, tc.payload) {
				t.Errorf("payload mismatch: got %x, want %x", plain, tc.payload)
			}
		})
	}
}

// TestDecryptSecureFrameRejectsMalformedTrailer verifies the trailer parser
// rejects frames with broken structure. (Tag-bit tampering is not detected
// because we don't verify the inner DAVE tag — see security note on
// newDAVEDecryptCipher.)
func TestDecryptSecureFrameRejectsMalformedTrailer(t *testing.T) {
	key := make([]byte, daveKeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("random key: %v", err)
	}
	encCipher, _ := newDAVECipher(key)
	decBlock, _ := newDAVEDecryptCipher(key)

	frame := encryptSecureFrame(encCipher, 42, []byte("opus payload that is reasonably long"))

	tests := []struct {
		name   string
		mutate func(b []byte) []byte
	}{
		{name: "broken magic marker", mutate: func(b []byte) []byte {
			out := append([]byte(nil), b...)
			out[len(out)-1] = 0xAB
			return out
		}},
		{name: "supplemental size larger than frame", mutate: func(b []byte) []byte {
			out := append([]byte(nil), b...)
			out[len(out)-3] = 0xFF
			return out
		}},
		{name: "supplemental size below minimum", mutate: func(b []byte) []byte {
			out := append([]byte(nil), b...)
			out[len(out)-3] = 0x05
			return out
		}},
		{name: "frame shorter than minimum trailer", mutate: func(b []byte) []byte {
			return []byte{0xFA, 0xFA}
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tampered := tt.mutate(frame)
			if _, _, err := decryptSecureFrame(decBlock, tampered); err == nil {
				t.Errorf("expected error, got nil")
			}
		})
	}
}

// TestDecryptSecureFrameWrongKey confirms that decrypt with a wrong key
// returns garbage (not an error) — this is the AES-CTR-without-auth tradeoff
// documented on newDAVEDecryptCipher. The downstream opus decoder will
// then fail to parse the garbage, which is the failure mode users see.
func TestDecryptSecureFrameWrongKey(t *testing.T) {
	key1 := make([]byte, daveKeySize)
	key2 := make([]byte, daveKeySize)
	rand.Read(key1)
	rand.Read(key2)

	encCipher, _ := newDAVECipher(key1)
	decBlock, _ := newDAVEDecryptCipher(key2)

	original := []byte("opus payload")
	frame := encryptSecureFrame(encCipher, 1, original)
	got, _, err := decryptSecureFrame(decBlock, frame)
	if err != nil {
		t.Fatalf("decrypt unexpectedly errored: %v", err)
	}
	if bytes.Equal(got, original) {
		t.Error("wrong-key decrypt produced original plaintext, expected garbage")
	}
}
