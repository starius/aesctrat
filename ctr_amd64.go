package aesctrat

import "fmt"

const BlockSize = 16

type AesCtr struct {
	expandedKeyEnc []uint32
	rounds         int
}

func NewAesCtr(key []byte) *AesCtr {
	var rounds int
	if len(key) == 16 {
		rounds = 10
	} else if len(key) == 24 {
		rounds = 12
	} else if len(key) == 32 {
		rounds = 14
	} else {
		panic(fmt.Sprintf("bad key length: %d", len(key)))
	}
	enc := make([]uint32, 4*(rounds+1))
	dec := make([]uint32, 4*(rounds+1)) // Throw away.
	expandKeyAsm(rounds, &key[0], &enc[0], &dec[0])
	return &AesCtr{
		expandedKeyEnc: enc,
		rounds:         rounds,
	}
}

func (c *AesCtr) XORKeyStreamAt(dst, src, iv []byte, offset uint64) {
	if len(iv) != BlockSize {
		panic(fmt.Sprintf("bad IV length: %d", len(iv)))
	}
	if len(dst) != len(src) {
		panic("len(dst) != len(src)")
	}
	if inexactOverlap(dst, src) {
		panic("invalid buffer overlap")
	}

	// Reverse IV once, because it is needed in reversed form
	// in all subsequent ASM calls.
	ivRev := make([]byte, BlockSize)
	copy(ivRev, iv)
	rev16Asm(&ivRev[0])

	offsetMod16 := offset % BlockSize

	if offsetMod16 != 0 {
		// We have a partial block in the beginning.
		plaintext := make([]byte, BlockSize)
		copy(plaintext[offsetMod16:BlockSize], src)
		ciphertext := make([]byte, BlockSize)
		ctrBlocks1Asm(c.rounds, &c.expandedKeyEnc[0], &ciphertext[0], &plaintext[0], &ivRev[0], offset/BlockSize)
		progress := BlockSize - offsetMod16
		if progress > uint64(len(src)) {
			progress = uint64(len(src))
		}
		copy(dst[:progress], ciphertext[offsetMod16:BlockSize])
		src = src[progress:]
		dst = dst[progress:]
		offset += progress
	}

	for len(src) >= 8*BlockSize {
		ctrBlocks8Asm(c.rounds, &c.expandedKeyEnc[0], &dst[0], &src[0], &ivRev[0], offset/BlockSize)
		src = src[8*BlockSize:]
		dst = dst[8*BlockSize:]
		offset += 8 * BlockSize
	}
	// 4, 2, and 1 blocks in the end can happen max 1 times, so if, not for.
	if len(src) >= 4*BlockSize {
		ctrBlocks4Asm(c.rounds, &c.expandedKeyEnc[0], &dst[0], &src[0], &ivRev[0], offset/BlockSize)
		src = src[4*BlockSize:]
		dst = dst[4*BlockSize:]
		offset += 4 * BlockSize
	}
	if len(src) >= 2*BlockSize {
		ctrBlocks2Asm(c.rounds, &c.expandedKeyEnc[0], &dst[0], &src[0], &ivRev[0], offset/BlockSize)
		src = src[2*BlockSize:]
		dst = dst[2*BlockSize:]
		offset += 2 * BlockSize
	}
	if len(src) >= 1*BlockSize {
		ctrBlocks1Asm(c.rounds, &c.expandedKeyEnc[0], &dst[0], &src[0], &ivRev[0], offset/BlockSize)
		src = src[1*BlockSize:]
		dst = dst[1*BlockSize:]
		offset += 1 * BlockSize
	}

	if len(src) != 0 {
		// We have a partial block in the end.
		plaintext := make([]byte, BlockSize)
		copy(plaintext, src)
		ciphertext := make([]byte, BlockSize)
		ctrBlocks1Asm(c.rounds, &c.expandedKeyEnc[0], &ciphertext[0], &plaintext[0], &ivRev[0], offset/BlockSize)
		copy(dst, ciphertext)
	}
}
