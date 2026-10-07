package session

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
)

const (
	// spillBlockSize is the unencrypted plaintext size per block (64 KiB).
	spillBlockSize = 64 * 1024

	// gcmTagSize is the standard 16-byte authentication tag for AES-GCM.
	gcmTagSize = 16

	// blockHeaderSize stores the 4-byte uint32 actual plaintext length.
	blockHeaderSize = 4

	// onDiskBlockSize is the fixed size of each encrypted block on disk (65556 bytes).
	onDiskBlockSize = blockHeaderSize + spillBlockSize + gcmTagSize
)

var (
	errCorruptSpill = errors.New("session: corrupt encrypted spill block")
)

type readCacheBlock struct {
	blockIndex uint64
	data       []byte
	actualLen  int
	valid      bool
}

type spillFile struct {
	mu           sync.Mutex
	file         *os.File
	key          []byte
	aead         cipher.AEAD
	nextBlock    uint64
	punchedBlock uint64
	cache        readCacheBlock
	closed       bool
}

func newSpillFile(dir string) (*spillFile, error) {
	if dir == "" {
		dir = os.TempDir()
	}
	f, err := os.CreateTemp(dir, "relay-spill-*")
	if err != nil {
		return nil, fmt.Errorf("create spill file: %w", err)
	}

	// Immediately unlink so the file is cleaned up automatically if process crashes
	_ = os.Remove(f.Name())

	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("generate spill key: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("aes new cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("cipher new gcm: %w", err)
	}

	return &spillFile{
		file: f,
		key:  key,
		aead: aead,
	}, nil
}

func (s *spillFile) makeNonce(blockIndex uint64) [12]byte {
	var nonce [12]byte
	binary.BigEndian.PutUint64(nonce[:8], blockIndex)
	return nonce
}

func (s *spillFile) makeAD(blockIndex uint64) [8]byte {
	var ad [8]byte
	binary.BigEndian.PutUint64(ad[:], blockIndex)
	return ad
}

// WriteBlock encrypts a single block of plaintext (up to 64 KiB) and writes it at blockIndex.
func (s *spillFile) WriteBlock(blockIndex uint64, plaintext []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}

	plainLen := len(plaintext)
	if plainLen > spillBlockSize {
		return fmt.Errorf("plaintext size %d exceeds block size %d", plainLen, spillBlockSize)
	}

	// Pad plaintext to fixed 64 KiB block size so disk stride is strictly constant
	var padded [spillBlockSize]byte
	copy(padded[:], plaintext)

	nonce := s.makeNonce(blockIndex)
	ad := s.makeAD(blockIndex)

	var diskBuf [onDiskBlockSize]byte
	binary.BigEndian.PutUint32(diskBuf[:blockHeaderSize], uint32(plainLen))

	// Encrypt in-place into diskBuf
	_ = s.aead.Seal(diskBuf[blockHeaderSize:blockHeaderSize], nonce[:], padded[:], ad[:])

	diskOffset := int64(blockIndex) * int64(onDiskBlockSize)
	if _, err := s.file.WriteAt(diskBuf[:], diskOffset); err != nil {
		return fmt.Errorf("write spill block %d: %w", blockIndex, err)
	}

	if blockIndex >= s.nextBlock {
		s.nextBlock = blockIndex + 1
	}

	// Invalidate read cache if this block was cached
	if s.cache.valid && s.cache.blockIndex == blockIndex {
		s.cache.valid = false
	}

	return nil
}

// ReadAt reads and decrypts bytes from the spill file starting at relative stream offset.
func (s *spillFile) ReadAt(relOffset uint64, dst []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, ErrClosed
	}

	totalRead := 0
	currOffset := relOffset

	for len(dst) > 0 {
		blockIndex := currOffset / spillBlockSize
		inBlockOffset := int(currOffset % spillBlockSize)

		var blockData []byte
		var actualLen int

		if s.cache.valid && s.cache.blockIndex == blockIndex {
			blockData = s.cache.data
			actualLen = s.cache.actualLen
		} else {
			diskOffset := int64(blockIndex) * int64(onDiskBlockSize)
			var diskBuf [onDiskBlockSize]byte
			if _, err := s.file.ReadAt(diskBuf[:], diskOffset); err != nil {
				return totalRead, err
			}

			actualLen = int(binary.BigEndian.Uint32(diskBuf[:blockHeaderSize]))
			if actualLen < 0 || actualLen > spillBlockSize {
				return totalRead, errCorruptSpill
			}

			nonce := s.makeNonce(blockIndex)
			ad := s.makeAD(blockIndex)

			plain, err := s.aead.Open(nil, nonce[:], diskBuf[blockHeaderSize:onDiskBlockSize], ad[:])
			if err != nil {
				return totalRead, errCorruptSpill
			}

			s.cache = readCacheBlock{
				blockIndex: blockIndex,
				data:       plain,
				actualLen:  actualLen,
				valid:      true,
			}
			blockData = plain
		}

		if inBlockOffset >= actualLen {
			break
		}

		avail := actualLen - inBlockOffset
		n := len(dst)
		if n > avail {
			n = avail
		}

		copy(dst[:n], blockData[inBlockOffset:inBlockOffset+n])
		dst = dst[n:]
		currOffset += uint64(n)
		totalRead += n
	}

	return totalRead, nil
}

// PunchHole reclaims disk blocks up to ackedRelOffset.
func (s *spillFile) PunchHole(ackedRelOffset uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}

	ackedBlocks := ackedRelOffset / spillBlockSize
	if ackedBlocks <= s.punchedBlock {
		return
	}

	numBlocks := ackedBlocks - s.punchedBlock
	punchStart := int64(s.punchedBlock) * int64(onDiskBlockSize)
	punchLen := int64(numBlocks) * int64(onDiskBlockSize)

	_ = punchHole(int(s.file.Fd()), punchStart, punchLen)
	s.punchedBlock = ackedBlocks
}

// Reset truncates the file back to 0 bytes and resets all block counters.
func (s *spillFile) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}

	_ = s.file.Truncate(0)
	_, _ = s.file.Seek(0, io.SeekStart)
	s.nextBlock = 0
	s.punchedBlock = 0
	s.cache.valid = false
}

// Close zeroes the ephemeral key in memory and closes the file descriptor.
func (s *spillFile) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true

	// Securely zero the AES key in RAM
	for i := range s.key {
		s.key[i] = 0
	}
	s.cache.valid = false
	s.cache.data = nil

	return s.file.Close()
}
