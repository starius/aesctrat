//go:build !amd64 && !arm64
// +build !amd64,!arm64

package aesctrat

func NewAesCtr(key []byte) *AesCtr {
	return newSlowAesCtr(key)
}

func (c *AesCtr) XORKeyStreamAt(dst, src, iv []byte, offset uint64) {
	c.slowXORKeyStreamAt(dst, src, iv, offset)
}
