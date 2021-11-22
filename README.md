# aesctrat [![GoDoc](https://pkg.go.dev/badge/github.com/starius/aesctrat)](https://pkg.go.dev/github.com/starius/aesctrat)

Fast implementation of seekable AES-CTR in Go

Inspired by experiments in https://github.com/mmcloughlin/aesnix

This implementation supports passing arbitrary offset,
which is useful to make IO in the middle of a file.

Implemented in ASM for amd64. Speedup is based on running
multiple AES instructions in a row to handle multiple blocks.
I think, the speedup is caused by instruction pipelining.

Other architectures use slow implementation based on
[crypto/aes](https://pkg.go.dev/crypto/aes).

On my machines slow implementation provides ~500 megabytes per second
and fast implementation — ~5000 megabytes. See results of the benchmark
in [results](results/) dir. I used Go version Go 1.17.1 on linux/amd64.

The implementation is compatible with
[crypto/cipher.NewCTR](https://pkg.go.dev/crypto/cipher#NewCTR).
(They produce the same stream of bytes.)
This is checked in the tests.

## Howto

```go
import "github.com/starius/aesctrat"

key := make([]byte, 16) // Or 24 or 32.
ctr := aesctrat.NewAesCtr(key)

iv := make([]byte, 16)
offset := uint64(5) // Skip 5 bytes.

plaintext := make([]byte, 1000)
file.ReadAt(plaintext, offset)
ciphertext := make([]byte, 1000) // Must be of the same length as plaintext.

ctr.XORKeyStreamAt(ciphertext, plaintext, iv, offset)
```

## Run tests on all architectures

Follow https://wiki.debian.org/QemuUserEmulation to install
QEMU User Emulation on your Debian machine.

```
for arch in $(go tool dist list | grep linux | sed 's@linux/@@'); do
  if GOARCH=$arch go test &> /tmp/$arch.log; then
    echo PASS $arch;
  else
    echo FAIL $arch;
  fi;
done
```

My results:

```
PASS 386
PASS amd64
PASS arm
PASS arm64
FAIL mips
PASS mips64
PASS mips64le
FAIL mipsle
PASS ppc64
PASS ppc64le
PASS riscv64
FAIL s390x
```

Failures:

```
head -2 /tmp/mips.log /tmp/mipsle.log /tmp/s390x.log
==> /tmp/mips.log <==
fatal error: float64nan
runtime: panic before malloc heap initialized

==> /tmp/mipsle.log <==
fatal error: float64nan
runtime: panic before malloc heap initialized

==> /tmp/s390x.log <==
signal: segmentation fault
FAIL   github.com/starius/aesctrat 0.015s
```

Those architectures crashed with `go test math/rand` so
I assume that those failures are not related to the package.
