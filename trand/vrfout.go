package trand

import (
	"github.com/minio/blake2b-simd"
)

type VRFOut struct {
	Height uint64
	Proof  []byte
}

// Sum256 obtain a 32 bytes randomness seed
func (vrf *VRFOut) Sum256() [32]byte {
	return blake2b.Sum256(vrf.Proof)
}
