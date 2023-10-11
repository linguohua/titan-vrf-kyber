package trand

// random number generator type
type RNGType = string

const (
	RNGType_Normal RNGType = "normal" // fast
	RNGType_Cipher RNGType = "cipher" // slow, but has cryptographically secure
)

type Random interface {
	Intn(n int) int
	Uint64() uint64
	Float64() float64
}

func New(seed [32]byte, typ RNGType) Random {
	switch typ {
	case RNGType_Cipher:
		return newChacha8(seed)
	case RNGType_Normal:
		fallthrough
	default:
		r := &xoshiro256{}
		r.Seed(seed)
		return r
	}
}
