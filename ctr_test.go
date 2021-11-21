package aesctrat

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"math/rand"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func randBytes(t testing.TB, r *rand.Rand, count int) []byte {
	t.Helper()
	buf := make([]byte, count)
	n, err := r.Read(buf)
	assert.NoError(t, err)
	assert.Equal(t, count, n)
	return buf
}

func TestAesCtr(t *testing.T) {
	r := rand.New(rand.NewSource(12345))

	const Size = 32 * 1024 * 1024

	plaintext := randBytes(t, r, Size)

	for _, keySize := range []int{16, 24, 32} {
		t.Run(fmt.Sprintf("keySize=%d", keySize), func(t *testing.T) {
			key := randBytes(t, r, keySize)
			iv := randBytes(t, r, BlockSize)

			// Generate reference ciphertext by crypto/cipher.
			aesBlock, err := aes.NewCipher(key)
			assert.NoError(t, err)
			stdCtr := cipher.NewCTR(aesBlock, iv)
			stdCiphertext := make([]byte, Size)
			stdCtr.XORKeyStream(stdCiphertext, plaintext)

			ctr := NewAesCtr(key)
			ciphertext := make([]byte, Size)

			// Split the range to random slices.
			const N = 1000
			boundaries := make([]int, 0, N+2)
			for i := 0; i < N; i++ {
				boundaries = append(boundaries, r.Intn(Size))
			}
			boundaries = append(boundaries, 0)
			boundaries = append(boundaries, Size)
			sort.Ints(boundaries)

			for _, i := range r.Perm(N + 1) {
				begin := boundaries[i]
				end := boundaries[i+1]
				ctr.XORKeyStreamAt(
					ciphertext[begin:end],
					plaintext[begin:end],
					iv, uint64(begin),
				)
			}

			assert.Equal(t, stdCiphertext, ciphertext)
		})
	}
}

func TestAesCtrEdgeCases(t *testing.T) {
	r := rand.New(rand.NewSource(54321))

	iv := randBytes(t, r, BlockSize)

	const Size = 200

	for _, keySize := range []int{16, 24, 32} {
		t.Run(fmt.Sprintf("keySize=%d", keySize), func(t *testing.T) {
			key := randBytes(t, r, keySize)

			ctr := NewAesCtr(key)

			plaintext := randBytes(t, r, Size)

			// Generate reference ciphertext by crypto/cipher.
			aesBlock, err := aes.NewCipher(key)
			assert.NoError(t, err)
			stdCtr := cipher.NewCTR(aesBlock, iv)
			stdCiphertext := make([]byte, len(plaintext))
			stdCtr.XORKeyStream(stdCiphertext, plaintext)

			for offset := 0; offset <= Size; offset++ {
				t.Run(fmt.Sprintf("offset=%d", offset), func(t *testing.T) {
					for size := 0; size <= Size-offset; size++ {
						t.Run(fmt.Sprintf("size=%d", size), func(t *testing.T) {
							ciphertext := make([]byte, Size)
							ctr.XORKeyStreamAt(
								ciphertext[offset:offset+size],
								plaintext[offset:offset+size],
								iv, uint64(offset),
							)
							assert.Equal(t,
								stdCiphertext[offset:offset+size],
								ciphertext[offset:offset+size],
							)
						})
					}
				})
			}
		})
	}
}

func parseHex(str string) []byte {
	b, err := hex.DecodeString(strings.ReplaceAll(str, " ", ""))
	if err != nil {
		panic(err)
	}
	return b
}

func TestAesCtrLowIvOverflow(t *testing.T) {
	r := rand.New(rand.NewSource(987654))

	const Size = 1024
	const ReserveForOffsets = 2048

	plaintext := randBytes(t, r, Size+ReserveForOffsets)

	ivs := [][]byte{
		parseHex("00 00 00 00 00 00 00 00   FF FF FF FF FF FF FF FF"),
		parseHex("FF FF FF FF FF FF FF FF   FF FF FF FF FF FF FF FF"),
		parseHex("FF FF FF FF FF FF FF FF   00 00 00 00 00 00 00 00"),
		parseHex("FF FF FF FF FF FF FF FF   FF FF FF FF FF FF FF fe"),
		parseHex("00 00 00 00 00 00 00 00   FF FF FF FF FF FF FF fe"),
		parseHex("FF FF FF FF FF FF FF FF   FF FF FF FF FF FF FF 00"),
		parseHex("00 00 00 00 00 00 00 01   FF FF FF FF FF FF FF 00"),
		parseHex("00 00 00 00 00 00 00 01   FF FF FF FF FF FF FF FF"),
		parseHex("00 00 00 00 00 00 00 01   FF FF FF FF FF FF FF fe"),
		parseHex("00 00 00 00 00 00 00 01   FF FF FF FF FF FF FF 00"),
	}

	for _, keySize := range []int{16, 24, 32} {
		t.Run(fmt.Sprintf("keySize=%d", keySize), func(t *testing.T) {
			for _, iv := range ivs {
				t.Run(fmt.Sprintf("iv=%s", hex.EncodeToString(iv)), func(t *testing.T) {
					for _, offset := range []int{0, 1, 16, 1024} {
						t.Run(fmt.Sprintf("offset=%d", offset), func(t *testing.T) {
							key := randBytes(t, r, keySize)

							// Generate reference ciphertext by crypto/cipher.
							aesBlock, err := aes.NewCipher(key)
							assert.NoError(t, err)
							stdCtr := cipher.NewCTR(aesBlock, iv)
							stdCiphertext := make([]byte, Size+ReserveForOffsets)
							stdCtr.XORKeyStream(stdCiphertext, plaintext)

							ctr := NewAesCtr(key)
							ciphertext := make([]byte, Size)

							ctr.XORKeyStreamAt(ciphertext, plaintext[offset:offset+Size], iv, uint64(offset))

							assert.Equal(t, stdCiphertext[offset:offset+Size], ciphertext)
						})
					}
				})
			}
		})
	}
}

func BenchmarkAesCtr(b *testing.B) {
	r := rand.New(rand.NewSource(12345))

	const Size = 32 * 1024 * 1024

	plaintext0 := randBytes(b, r, Size+16)
	ciphertext0 := make([]byte, Size+16)

	for _, keySize := range []int{16, 24, 32} {
		b.Run(fmt.Sprintf("keySize=%d", keySize), func(b *testing.B) {
			for _, shift := range []int{0, 1, 8, 14} {
				b.Run(fmt.Sprintf("shift=%d", shift), func(b *testing.B) {
					for _, offset := range []int{0, 1, 16, 1024} {
						b.Run(fmt.Sprintf("offset=%d", offset), func(b *testing.B) {
							plaintext := plaintext0[shift : Size+shift]
							ciphertext := ciphertext0[shift : Size+shift]

							key := randBytes(b, r, keySize)
							iv := randBytes(b, r, BlockSize)

							ctr := NewAesCtr(key)

							b.SetBytes(int64(len(plaintext)))
							b.ResetTimer()

							for j := 0; j < b.N; j++ {
								ctr.XORKeyStreamAt(ciphertext, plaintext, iv, uint64(offset))
							}
						})
					}
				})
			}
		})
	}
}
