package trand

import (
	"unsafe"

	cc "github.com/nixberg/chacha-rng-go"
)

type chacha8 struct {
	s *cc.ChaCha
}

func newChacha8(seed [32]byte) *chacha8 {
	p := unsafe.Pointer(&seed)
	seed32s := unsafe.Slice((*uint32)(p), 8)
	var seed32 [8]uint32
	for i := 0; i < 8; i++ {
		seed32[i] = seed32s[i]
	}

	s := cc.Seeded8(seed32, 0)
	return &chacha8{
		s: s,
	}
}

func (c *chacha8) Uint64() uint64 {
	return c.s.Uint64()
}

func (c *chacha8) Float64() float64 {
	return c.s.Float64()
}

func (c *chacha8) Intn(n int) int {
	return int(c.Float64() * float64(n))
}
