package trand

import (
	"github.com/minio/blake2b-simd"
)

type VRFOut struct {
	Height uint64
	Proof  []byte
}

func (vrf *VRFOut) Sum256() [32]byte {
	return blake2b.Sum256(vrf.Proof)
}
