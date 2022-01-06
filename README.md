# aesctrat [![GoDoc](https://pkg.go.dev/badge/github.com/starius/aesctrat)](https://pkg.go.dev/github.com/starius/aesctrat)

Fast implementation of seekable AES-CTR in Go

Inspired by experiments in https://github.com/mmcloughlin/aesnix

This implementation supports passing arbitrary offset,
which is useful to make IO in the middle of a file.

Implemented in ASM for amd64 and arm64. Speedup is based on running
multiple AES instructions in a row to handle multiple blocks.
I think, the speedup is caused by instruction pipelining.

Other architectures use slow implementation based on
[crypto/aes](https://pkg.go.dev/crypto/aes).

On my machines slow implementation provides ~500 megabytes per second
and fast implementation — ~5000 megabytes.

The implementation is compatible with
[crypto/cipher.NewCTR](https://pkg.go.dev/crypto/cipher#NewCTR).
(They produce the same stream of bytes.)
This is checked in the tests.

## Benchmarks

![aes_benchmark](https://user-images.githubusercontent.com/7602655/148282052-03345482-520e-4a7a-8638-ecf9b18c790b.png)


| CPU                 | std.CTR | std.GCM/Seal | aesctrat.slow | aesctrat.fast | Speedup (std.CTR -> aesctrat.fast) |
|---------------------|---------|--------------|---------------|---------------|------------------------------------|
| amd64-epyc          | 421.19  | 2829.11      | 470.17        | 5443.96       | 12.9x                              |
| amd64-ryzen5        | 906.12  | 4302.75      | 649.95        | 6119.56       | 6.8x                               |
| arm64-ec2-t4g-small | 865.65  | 1698.73      | 341.89        | 2313.64       | 2.7x                               |
| arm64-darwin-m1     | 1929.33 | 6546.48      | 768.86        | 7285.88       | 3.8x                               |

Raw output of `go test -bench .` and `go test -bench . crypto/aes crypto/cipher`
in [results](results/) dir.

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
