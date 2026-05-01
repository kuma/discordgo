package discordgo

import (
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"strconv"
	"sync"
)

type DAVESession struct {
	mu                  sync.Mutex
	protocolVersion     int
	epoch               uint64
	pendingTransitionID uint16
	pendingVersion      int

	exporterSecret    []byte
	senderKey         []byte
	senderNonce       uint32
	frameCipher       cipher.AEAD
	userID            string
	active            bool
	ratchetBaseSecret []byte
	currentGeneration uint32
	hasPendingKey     bool

	// remoteSenders tracks decrypt state for other speakers in the group,
	// keyed by user ID. Entries are created lazily on the first frame from
	// each sender and reset on epoch transitions.
	remoteSenders map[string]*daveRemoteSender

	kpBundle *mlsKeyPackageBundle
}

// daveRemoteSender holds the receive-side ratchet state for one remote
// member. We retain two generations (current and previous) so out-of-order
// late frames from the prior generation still decrypt — per the DAVE spec,
// keys remain valid for ~10 seconds across generation rollover.
type daveRemoteSender struct {
	userID            string
	ratchetBaseSecret []byte

	currentGen   uint32
	currentBlock cipher.Block

	prevGen   uint32
	prevBlock cipher.Block
	havePrev  bool
}

func NewDAVESession(userID string) *DAVESession {
	return &DAVESession{
		userID:        userID,
		remoteSenders: make(map[string]*daveRemoteSender),
	}
}

func (d *DAVESession) GenerateKeyPackage() ([]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.generateKeyPackageLocked()
}

func (d *DAVESession) ResetForReWelcome() ([]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.active = false
	d.senderKey = nil
	d.frameCipher = nil
	d.exporterSecret = nil
	d.ratchetBaseSecret = nil
	d.currentGeneration = 0
	d.hasPendingKey = false
	d.remoteSenders = make(map[string]*daveRemoteSender)

	return d.generateKeyPackageLocked()
}

func (d *DAVESession) generateKeyPackageLocked() ([]byte, error) {
	bundle, err := mlsGenerateKeyPackage(d.userID)
	if err != nil {
		return nil, fmt.Errorf("generating key package: %w", err)
	}
	d.kpBundle = bundle
	return bundle.serialized, nil
}

func (d *DAVESession) HandleExternalSenderPackage(data []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return nil
}

func (d *DAVESession) HandleWelcome(data []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.kpBundle == nil {
		return fmt.Errorf("no key package generated")
	}

	result, err := mlsProcessWelcome(data, d.kpBundle)
	if err != nil {
		return fmt.Errorf("processing welcome: %w", err)
	}

	d.exporterSecret = result.exporterSecret
	d.epoch = result.epoch
	d.hasPendingKey = true
	return nil
}

func (d *DAVESession) HandleCommit(data []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return nil
}

func (d *DAVESession) HandlePrepareTransition(transitionID uint16, protocolVersion int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.pendingTransitionID = transitionID
	d.pendingVersion = protocolVersion
}

func (d *DAVESession) HandleExecuteTransition(transitionID uint16) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if transitionID != d.pendingTransitionID {
		if d.senderKey != nil {
			d.active = true
		}
		return nil
	}

	if d.pendingVersion > 0 {
		if d.hasPendingKey && d.exporterSecret != nil {
			if err := d.deriveSenderKeyLocked(); err != nil {
				return err
			}
			d.hasPendingKey = false
		}
		if d.senderKey == nil {
			return nil
		}
		d.active = true
	} else {
		d.active = false
		d.senderKey = nil
		d.frameCipher = nil
		d.hasPendingKey = false
	}
	return nil
}

func (d *DAVESession) HandlePrepareEpoch(epoch uint64, protocolVersion int) ([]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.epoch = epoch
	d.active = false
	d.senderKey = nil
	d.frameCipher = nil
	d.exporterSecret = nil
	d.remoteSenders = make(map[string]*daveRemoteSender)

	return d.generateKeyPackageLocked()
}

func (d *DAVESession) DeriveSenderKey() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.deriveSenderKeyLocked()
}

func (d *DAVESession) deriveSenderKeyLocked() error {
	if d.exporterSecret == nil {
		return fmt.Errorf("no exporter secret")
	}

	userIDNum, err := strconv.ParseUint(d.userID, 10, 64)
	if err != nil {
		return fmt.Errorf("parsing user ID: %w", err)
	}
	context := make([]byte, 8)
	binary.LittleEndian.PutUint64(context, userIDNum)

	baseSecret, err := mlsExport(d.exporterSecret, daveExportLabel, context, daveKeySize)
	if err != nil {
		return fmt.Errorf("exporting base secret: %w", err)
	}

	d.ratchetBaseSecret = baseSecret
	d.currentGeneration = 0
	d.senderNonce = 0

	key, err := hashRatchetGetKey(baseSecret, 0)
	if err != nil {
		return fmt.Errorf("deriving ratchet key: %w", err)
	}
	d.senderKey = key

	frameCipher, err := newDAVECipher(key)
	if err != nil {
		return fmt.Errorf("creating frame cipher: %w", err)
	}
	d.frameCipher = frameCipher
	return nil
}

func (d *DAVESession) EncryptFrame(opusData []byte) ([]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.frameCipher == nil {
		return nil, fmt.Errorf("no frame cipher")
	}

	d.senderNonce++

	generation := d.senderNonce >> 24
	if generation != d.currentGeneration {
		d.currentGeneration = generation
		key, err := hashRatchetGetKey(d.ratchetBaseSecret, generation)
		if err != nil {
			return nil, fmt.Errorf("ratcheting key for generation %d: %w", generation, err)
		}
		d.senderKey = key
		frameCipher, err := newDAVECipher(key)
		if err != nil {
			return nil, fmt.Errorf("creating cipher for generation %d: %w", generation, err)
		}
		d.frameCipher = frameCipher
	}

	encrypted := encryptSecureFrame(d.frameCipher, d.senderNonce, opusData)
	return encrypted, nil
}

func (d *DAVESession) IsActive() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.active
}

func (d *DAVESession) Reset() {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.exporterSecret = nil
	d.senderKey = nil
	d.senderNonce = 0
	d.frameCipher = nil
	d.active = false
	d.kpBundle = nil
	d.pendingTransitionID = 0
	d.pendingVersion = 0
	d.ratchetBaseSecret = nil
	d.currentGeneration = 0
	d.hasPendingKey = false
	d.remoteSenders = make(map[string]*daveRemoteSender)
}

// DecryptFrame decrypts a DAVE SecureFrame received from the named sender.
// Returns the plaintext media bytes (typically Opus). The session must be
// active (Welcome+ExecuteTransition completed); otherwise returns an error.
//
// Per-sender state is created lazily on the first frame from each sender
// and reset on epoch transitions. The current and previous generation keys
// are retained so out-of-order late frames from the prior generation still
// decrypt — older generations are evicted on rollover.
//
// Tag verification is NOT performed; see security note on
// newDAVEDecryptCipher. Wrong-key decryption produces garbage that the
// downstream codec will fail to parse.
func (d *DAVESession) DecryptFrame(senderUserID string, encrypted []byte) ([]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if !d.active {
		return nil, fmt.Errorf("DAVE session not active")
	}
	if d.exporterSecret == nil {
		return nil, fmt.Errorf("no exporter secret")
	}
	if senderUserID == "" {
		return nil, fmt.Errorf("empty sender user ID")
	}

	parts, err := parseSecureFrame(encrypted)
	if err != nil {
		return nil, fmt.Errorf("parse SecureFrame: %w", err)
	}

	sender, err := d.getOrCreateRemoteSenderLocked(senderUserID)
	if err != nil {
		return nil, fmt.Errorf("init sender %s: %w", senderUserID, err)
	}

	generation := parts.nonce >> 24
	block, err := sender.blockForGeneration(generation)
	if err != nil {
		return nil, fmt.Errorf("derive key for generation %d: %w", generation, err)
	}

	return aesCTRDecryptFrame(block, parts.ciphertext, parts.nonce), nil
}

// getOrCreateRemoteSenderLocked returns the receive-side state for senderID,
// creating and seeding the ratchet base secret on first use. Caller must
// hold d.mu.
func (d *DAVESession) getOrCreateRemoteSenderLocked(senderID string) (*daveRemoteSender, error) {
	if d.remoteSenders == nil {
		d.remoteSenders = make(map[string]*daveRemoteSender)
	}
	if s, ok := d.remoteSenders[senderID]; ok {
		return s, nil
	}

	userIDNum, err := strconv.ParseUint(senderID, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("parsing sender user ID: %w", err)
	}
	context := make([]byte, 8)
	binary.LittleEndian.PutUint64(context, userIDNum)

	baseSecret, err := mlsExport(d.exporterSecret, daveExportLabel, context, daveKeySize)
	if err != nil {
		return nil, fmt.Errorf("exporting sender base secret: %w", err)
	}

	s := &daveRemoteSender{
		userID:            senderID,
		ratchetBaseSecret: baseSecret,
	}
	d.remoteSenders[senderID] = s
	return s, nil
}

// blockForGeneration returns the AES block cipher for the given generation,
// reusing the cached entry if present. Maintains a two-slot history
// (current + previous) so out-of-order late frames still decrypt.
// Generations older than previous are rejected, matching the DAVE spec's
// ~10s key retention window in spirit (forward secrecy intent).
func (s *daveRemoteSender) blockForGeneration(generation uint32) (cipher.Block, error) {
	// Cold start: first frame from this sender.
	if s.currentBlock == nil {
		block, err := s.deriveBlock(generation)
		if err != nil {
			return nil, err
		}
		s.currentGen = generation
		s.currentBlock = block
		return block, nil
	}

	// Cache hits.
	if generation == s.currentGen {
		return s.currentBlock, nil
	}
	if s.havePrev && generation == s.prevGen {
		return s.prevBlock, nil
	}

	// Forward jump: derive new, slide current → prev (evicting old prev).
	if generation > s.currentGen {
		block, err := s.deriveBlock(generation)
		if err != nil {
			return nil, err
		}
		s.prevGen = s.currentGen
		s.prevBlock = s.currentBlock
		s.havePrev = true
		s.currentGen = generation
		s.currentBlock = block
		return block, nil
	}

	// Backward arrival exactly one generation old, prev slot empty (or
	// caller forward-jumped past it). Fill the prev slot — within window.
	if generation == s.currentGen-1 && !s.havePrev {
		block, err := s.deriveBlock(generation)
		if err != nil {
			return nil, err
		}
		s.prevGen = generation
		s.prevBlock = block
		s.havePrev = true
		return block, nil
	}

	// Older than two generations behind — reject per retention window.
	return nil, fmt.Errorf("generation %d older than retained window (current=%d, prev=%d, havePrev=%t)",
		generation, s.currentGen, s.prevGen, s.havePrev)
}

// deriveBlock computes the AES block cipher for a specific ratchet
// generation from the sender's base secret.
func (s *daveRemoteSender) deriveBlock(generation uint32) (cipher.Block, error) {
	key, err := hashRatchetGetKey(s.ratchetBaseSecret, generation)
	if err != nil {
		return nil, fmt.Errorf("ratchet key for generation %d: %w", generation, err)
	}
	block, err := newDAVEDecryptCipher(key)
	if err != nil {
		return nil, fmt.Errorf("AES block for generation %d: %w", generation, err)
	}
	return block, nil
}
