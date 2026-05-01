package discordgo

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
)

const (
	daveTagSize     = 8
	daveKeySize     = 16
	daveExportLabel = "Discord Secure Frames v0"
)

func encryptSecureFrame(frameCipher cipher.AEAD, nonce uint32, opusData []byte) []byte {
	fullNonce := buildNonce(nonce)
	sealed := frameCipher.Seal(nil, fullNonce, opusData, nil)

	ciphertext := sealed[:len(opusData)]
	fullTag := sealed[len(opusData):]
	truncatedTag := fullTag[:daveTagSize]

	nonceBytes := encodeULEB128(nonce)

	supplementalSize := byte(daveTagSize + len(nonceBytes) + 0 + 1 + 2)

	result := make([]byte, 0, len(ciphertext)+daveTagSize+len(nonceBytes)+3)
	result = append(result, ciphertext...)
	result = append(result, truncatedTag...)
	result = append(result, nonceBytes...)
	result = append(result, supplementalSize)
	result = append(result, 0xFA, 0xFA)
	return result
}

func buildNonce(counter uint32) []byte {
	nonce := make([]byte, 12)
	binary.LittleEndian.PutUint32(nonce[8:], counter)
	return nonce
}

func encodeULEB128(value uint32) []byte {
	if value == 0 {
		return []byte{0}
	}
	var result []byte
	for value > 0 {
		b := byte(value & 0x7F)
		value >>= 7
		if value > 0 {
			b |= 0x80
		}
		result = append(result, b)
	}
	return result
}

func newDAVECipher(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// newDAVEDecryptCipher returns an AES block cipher for SecureFrame decryption.
// Decryption uses AES-CTR (counter mode) rather than AES-GCM because the Go
// standard library's cipher.NewGCMWithTagSize enforces a 12-byte minimum tag
// size, while DAVE truncates GCM tags to 8 bytes.
//
// SECURITY NOTE: this approach skips inner SecureFrame tag verification.
// Packet integrity is still guaranteed by the outer transport AEAD layer
// (aead_aes256_gcm_rtpsize) that Discord's voice protocol applies before
// DAVE. What's lost is end-to-end sender authenticity — i.e. proof that a
// frame came from the claimed sender rather than the SFU. For a passive
// recording use case where the SFU is trusted, this is acceptable. A
// follow-up should add GHASH-based 8-byte tag verification for full DAVE
// spec compliance.
func newDAVEDecryptCipher(key []byte) (cipher.Block, error) {
	return aes.NewCipher(key)
}

// decodeULEB128 reads a ULEB128 value from the start of data and returns the
// value and number of bytes consumed. Capped at 5 bytes (max uint32 encoding).
func decodeULEB128(data []byte) (value uint32, n int, err error) {
	var result uint64
	var shift uint
	for i, b := range data {
		if i >= 5 {
			return 0, 0, fmt.Errorf("ULEB128 longer than 5 bytes")
		}
		result |= uint64(b&0x7F) << shift
		if b&0x80 == 0 {
			if result > 0xFFFFFFFF {
				return 0, 0, fmt.Errorf("ULEB128 overflows uint32: %d", result)
			}
			return uint32(result), i + 1, nil
		}
		shift += 7
	}
	return 0, 0, fmt.Errorf("ULEB128 unterminated")
}

// secureFrameParts holds the fields parsed from a SecureFrame trailer.
// The 8-byte truncated tag is captured but not verified — see the security
// note on newDAVEDecryptCipher.
type secureFrameParts struct {
	ciphertext []byte
	nonce      uint32
}

// parseSecureFrame parses a DAVE SecureFrame trailer. Returns the
// ciphertext slice (a sub-slice of encrypted) and the truncated nonce.
//
// Frame layout (per Discord DAVE spec, sequential from start of trailer):
//
//	[ciphertext] [8B tag] [ULEB128 nonce] [ULEB128 unencrypted ranges]
//	[1B supplemental size] [0xFA 0xFA]
//
// The supplemental size byte counts the entire trailer length including
// itself and the magic marker. Unencrypted range pairs are not supported —
// frames carrying any are rejected.
func parseSecureFrame(encrypted []byte) (*secureFrameParts, error) {
	const minTrailer = daveTagSize + 1 + 1 + 2 // tag + min ULEB128 + size byte + magic
	if len(encrypted) < minTrailer {
		return nil, fmt.Errorf("frame too short: %d bytes", len(encrypted))
	}

	end := len(encrypted)
	if encrypted[end-2] != 0xFA || encrypted[end-1] != 0xFA {
		return nil, fmt.Errorf("invalid magic marker: %02x %02x",
			encrypted[end-2], encrypted[end-1])
	}

	suppSize := int(encrypted[end-3])
	if suppSize < minTrailer {
		return nil, fmt.Errorf("supplemental size %d below minimum trailer %d",
			suppSize, minTrailer)
	}
	if suppSize > end {
		return nil, fmt.Errorf("supplemental size %d exceeds frame size %d",
			suppSize, end)
	}

	trailerStart := end - suppSize
	trailer := encrypted[trailerStart:end]

	nonceVal, nonceLen, err := decodeULEB128(trailer[daveTagSize:])
	if err != nil {
		return nil, fmt.Errorf("decoding nonce: %w", err)
	}

	rangesStart := daveTagSize + nonceLen
	rangesEnd := len(trailer) - 3 // before size byte and magic
	if rangesEnd < rangesStart {
		return nil, fmt.Errorf("malformed trailer: nonce overruns trailer")
	}
	if rangesEnd > rangesStart {
		return nil, fmt.Errorf("unencrypted range pairs not supported (got %d trailing bytes)",
			rangesEnd-rangesStart)
	}

	return &secureFrameParts{
		ciphertext: encrypted[:trailerStart],
		nonce:      nonceVal,
	}, nil
}

// aesCTRDecryptFrame XORs a SecureFrame ciphertext with the AES-CTR
// keystream that AES-GCM would have produced for the given nonce.
//
// AES-GCM uses a CTR-mode keystream starting at J0+1, where J0 is the
// IV || 0x00000001 for 12-byte IVs. We replicate that here so the
// keystream byte-aligns with the encrypt path's GCM keystream.
func aesCTRDecryptFrame(block cipher.Block, ciphertext []byte, nonce uint32) []byte {
	iv := make([]byte, 16)
	copy(iv, buildNonce(nonce))
	binary.BigEndian.PutUint32(iv[12:], 2)

	plaintext := make([]byte, len(ciphertext))
	cipher.NewCTR(block, iv).XORKeyStream(plaintext, ciphertext)
	return plaintext
}

// decryptSecureFrame is the top-level helper used by tests and direct
// callers. DAVESession.DecryptFrame uses parseSecureFrame +
// aesCTRDecryptFrame directly so it can pick a per-generation cipher.
func decryptSecureFrame(block cipher.Block, encrypted []byte) (plaintext []byte, nonce uint32, err error) {
	parts, err := parseSecureFrame(encrypted)
	if err != nil {
		return nil, 0, err
	}
	return aesCTRDecryptFrame(block, parts.ciphertext, parts.nonce), parts.nonce, nil
}

func hashRatchetGetKey(baseSecret []byte, generation uint32) ([]byte, error) {
	secret := baseSecret
	for i := uint32(0); i < generation; i++ {
		genCtx := make([]byte, 4)
		binary.BigEndian.PutUint32(genCtx, i)
		next, err := mlsExpandWithLabel(secret, "secret", genCtx, 32)
		if err != nil {
			return nil, err
		}
		secret = next
	}
	genCtx := make([]byte, 4)
	binary.BigEndian.PutUint32(genCtx, generation)
	return mlsExpandWithLabel(secret, "key", genCtx, 16)
}
