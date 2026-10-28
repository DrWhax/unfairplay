package recovery

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	_ "embed"
	"fmt"
	"io"
	"sync"
)

// This profile contains only exact-26A428 blocks with a real branch, call, or
// return terminator. Every start already present in the verified profiles was
// used as a boundary and excluded from this fallback.
//
//go:embed profiles/macos26a428-safe-extracted.bin.gz
var compact26A428SafeExtractedCompressed []byte

var (
	compact26A428SafeExtractedOnce   sync.Once
	compact26A428SafeExtractedBlocks map[uint64]compactBlock
	compact26A428SafeExtractedErr    error
)

func loadCompact26A428SafeExtractedBlocks() (map[uint64]compactBlock, error) {
	compact26A428SafeExtractedOnce.Do(func() {
		expected := [32]byte{
			0x66, 0x01, 0x4b, 0x69, 0xe8, 0x0e, 0x71, 0xed,
			0xe5, 0x58, 0x50, 0xc1, 0xd5, 0x35, 0xe1, 0x0d,
			0x3b, 0xee, 0xb8, 0x01, 0x9d, 0x7b, 0xd9, 0x68,
			0x75, 0x3d, 0x4a, 0x5f, 0x14, 0x0d, 0x35, 0x44,
		}
		if sha256.Sum256(compact26A428SafeExtractedCompressed) != expected {
			compact26A428SafeExtractedErr = fmt.Errorf("safe extracted FairPlay profile digest mismatch")
			return
		}
		stream, err := gzip.NewReader(bytes.NewReader(compact26A428SafeExtractedCompressed))
		if err != nil {
			compact26A428SafeExtractedErr = err
			return
		}
		encoded, readErr := io.ReadAll(io.LimitReader(stream, 32*1024*1024+1))
		closeErr := stream.Close()
		defer clear(encoded)
		if readErr != nil {
			compact26A428SafeExtractedErr = readErr
			return
		}
		if closeErr != nil {
			compact26A428SafeExtractedErr = closeErr
			return
		}
		if len(encoded) > 32*1024*1024 {
			compact26A428SafeExtractedErr = fmt.Errorf("safe extracted FairPlay profile is too large")
			return
		}
		sections, err := unmarshalCompactProfile(encoded)
		if err != nil {
			compact26A428SafeExtractedErr = err
			return
		}
		if len(sections) != 1 || len(sections[11]) != 52_494 {
			compact26A428SafeExtractedErr = fmt.Errorf("safe extracted FairPlay profile has invalid geometry")
			return
		}
		compact26A428SafeExtractedBlocks = sections[11]
	})
	return compact26A428SafeExtractedBlocks, compact26A428SafeExtractedErr
}
