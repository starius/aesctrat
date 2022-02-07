package aesctrat

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
)

const BlockSize = 16

type AesCtr struct {
	// For fast.
	expandedKeyEnc []uint32
	rounds         int

	// For slow.
	aesCipher cipher.Block
}

func newSlowAesCtr(key []byte) *AesCtr {
	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	return &AesCtr{
		aesCipher: aesCipher,
	}
}

func (c *AesCtr) slowXORKeyStreamAt(dst, src, iv []byte, offset uint64) {
	if len(iv) != BlockSize {
		panic(fmt.Sprintf("bad IV length: %d", len(iv)))
	}
	if len(dst) != len(src) {
		panic("len(dst) != len(src)")
	}
	if inexactOverlap(dst, src) {
		panic("invalid buffer overlap")
	}

	ivHigh := binary.BigEndian.Uint64(iv[0:8])
	ivLow := binary.BigEndian.Uint64(iv[8:16])

	buf := make([]byte, BlockSize)
	makeAt := func(blockIndex uint64) {
		low := ivLow + blockIndex
		high := ivHigh
		if low < ivLow {
			// Overflow.
			high++
		}
		binary.BigEndian.PutUint64(buf[0:8], high)
		binary.BigEndian.PutUint64(buf[8:16], low)
		c.aesCipher.Encrypt(buf, buf)
	}

	offsetMod16 := offset % BlockSize

	if offsetMod16 != 0 {
		// We have a partial block in the beginning.
		makeAt(offset / BlockSize)
		progress := BlockSize - offsetMod16
		if progress > uint64(len(src)) {
			progress = uint64(len(src))
		}
		xor(dst[:progress], src[:progress], buf[offsetMod16:BlockSize])
		src = src[progress:]
		dst = dst[progress:]
		offset += progress
	}

	for len(src) >= BlockSize {
		makeAt(offset / BlockSize)
		xor(dst, src, buf)
		src = src[BlockSize:]
		dst = dst[BlockSize:]
		offset += BlockSize
	}

	if len(src) != 0 {
		// We have a partial block in the end.
		makeAt(offset / BlockSize)
		xor(dst, src, buf)
	}
}

// Download xor_* files from Go standard lib.
//go:generate sh -c "curl --silent https://raw.githubusercontent.com/golang/go/2c76a6f7f85365cefb5200b2b3408fd6bd421b3d/src/crypto/cipher/xor_amd64.go > xor_amd64.go"
//go:generate sh -c "curl --silent https://raw.githubusercontent.com/golang/go/2c76a6f7f85365cefb5200b2b3408fd6bd421b3d/src/crypto/cipher/xor_amd64.s > xor_amd64.s"
//go:generate sh -c "curl --silent https://raw.githubusercontent.com/golang/go/2c76a6f7f85365cefb5200b2b3408fd6bd421b3d/src/crypto/cipher/xor_arm64.go > xor_arm64.go"
//go:generate sh -c "curl --silent https://raw.githubusercontent.com/golang/go/2c76a6f7f85365cefb5200b2b3408fd6bd421b3d/src/crypto/cipher/xor_arm64.s > xor_arm64.s"
//go:generate sh -c "curl --silent https://raw.githubusercontent.com/golang/go/2c76a6f7f85365cefb5200b2b3408fd6bd421b3d/src/crypto/cipher/xor_generic.go > xor_generic.go"
//go:generate sh -c "curl --silent https://raw.githubusercontent.com/golang/go/2c76a6f7f85365cefb5200b2b3408fd6bd421b3d/src/crypto/cipher/xor_ppc64x.go > xor_ppc64x.go"
//go:generate sh -c "curl --silent https://raw.githubusercontent.com/golang/go/2c76a6f7f85365cefb5200b2b3408fd6bd421b3d/src/crypto/cipher/xor_ppc64x.s > xor_ppc64x.s"
//go:generate sh -c "sed 's/package cipher/package aesctrat/' -i xor*"

func xor(dst, src1, src2 []byte) {
	n := len(dst)
	if len(src1) < n {
		n = len(src1)
	}
	if len(src2) < n {
		n = len(src2)
	}
	_ = xorBytes(dst, src1, src2)
}
