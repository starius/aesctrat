package aesctrat

import (
	"crypto/aes"
	"crypto/cipher"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
)

type CtrEncryptor func(nr int, xk *uint32, dst, src, iv *byte, blockIndex uint64)

var v = struct {
	Rounds int
	Key    []byte
	Plain  []byte
	Cipher []byte
}{
	Rounds: 10,
	Key: []byte{
		0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
		0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
	},
	Plain: []byte{
		0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
		0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
	},
	Cipher: []byte{
		0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60,
		0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97,
	},
}

var ctrCases = []struct {
	CtrEncryptor CtrEncryptor
	Blocks       int
}{
	{ctrBlocks1Asm, 1},
	{ctrBlocks2Asm, 2},
	{ctrBlocks4Asm, 4},
	{ctrBlocks8Asm, 8},
}

func TestMultiCTR(t *testing.T) {
	enc := make([]uint32, 4*(v.Rounds+1))
	dec := make([]uint32, 4*(v.Rounds+1))
	expandKeyAsm(v.Rounds, &v.Key[0], &enc[0], &dec[0])

	for _, c := range ctrCases {
		t.Run(strconv.Itoa(c.Blocks), func(t *testing.T) {
			iv := []byte{
				0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
				0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
			}
			plaintext := make([]byte, 16*c.Blocks)
			ciphertext := make([]byte, 16*c.Blocks)
			blockIndex := uint64(0)

			ivRev := make([]byte, len(iv))
			copy(ivRev, iv)
			rev16Asm(&ivRev[0])

			c.CtrEncryptor(v.Rounds, &enc[0], &ciphertext[0], &plaintext[0], &ivRev[0], blockIndex)

			assert.Equal(t, v.Cipher, ciphertext[0:16])

			// Compare to crypto/cipher.
			aesBlock, err := aes.NewCipher(v.Key)
			assert.NoError(t, err)
			stdCtr := cipher.NewCTR(aesBlock, iv)
			stdCiphertext := make([]byte, 16*c.Blocks)
			stdCtr.XORKeyStream(stdCiphertext, stdCiphertext)

			assert.Equal(t, stdCiphertext, ciphertext)
		})
	}
}

func BenchmarkMultiCTR(b *testing.B) {
	for _, c := range ctrCases {
		b.Run(strconv.Itoa(c.Blocks), func(b *testing.B) {
			EncryptorBenchmarkCTR(b, c.CtrEncryptor, c.Blocks)
		})
	}
}

func EncryptorBenchmarkCTR(b *testing.B, f CtrEncryptor, blocks int) {
	enc := make([]uint32, 4*(v.Rounds+1))
	dec := make([]uint32, 4*(v.Rounds+1))
	expandKeyAsm(v.Rounds, &v.Key[0], &enc[0], &dec[0])

	iv := make([]byte, 16)
	plaintext := make([]byte, 16*blocks+1)[1:]
	ciphertext := make([]byte, 16*blocks+1)[1:]
	blockIndex := uint64(0)

	b.SetBytes(16 * int64(blocks))
	b.ResetTimer()

	for j := 0; j < b.N; j++ {
		f(v.Rounds, &enc[0], &ciphertext[0], &plaintext[0], &iv[0], blockIndex)
	}
}

func TestRev16(t *testing.T) {
	iv := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	rev16Asm(&iv[0])
	assert.Equal(t, []byte{15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0}, iv)
}
