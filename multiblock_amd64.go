package aesctrat

//go:generate sh -c "PYTHONIOENCODING=utf8 python multiblock_gen.py 1,2,4,8 > multiblock_amd64.s"

// Download asm_amd64.s and cut expandKeyAsm only.
//go:generate sh -c "curl --silent https://raw.githubusercontent.com/golang/go/b81735924936291303559fd71dabaa1aa88f57c5/src/crypto/aes/asm_amd64.s > _asm_amd64.s"
//go:generate sh -c "head --lines 5 _asm_amd64.s > asm_amd64.s"
//go:generate sh -c "tail --lines +104 _asm_amd64.s >> asm_amd64.s"
//go:generate sh -c "rm _asm_amd64.s"

func expandKeyAsm(nr int, key *byte, enc *uint32, dec *uint32)

func rev16Asm(iv *byte)

func ctrBlocks1Asm(nr int, xk *uint32, dst, src, ivRev *byte, blockIndex uint64)
func ctrBlocks2Asm(nr int, xk *uint32, dst, src, ivRev *byte, blockIndex uint64)
func ctrBlocks4Asm(nr int, xk *uint32, dst, src, ivRev *byte, blockIndex uint64)
func ctrBlocks8Asm(nr int, xk *uint32, dst, src, ivRev *byte, blockIndex uint64)
