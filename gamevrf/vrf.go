package gamevrf

import (
	"sync"
	"time"
	"titan-vrf/filrpc"
	"titan-vrf/trand"

	"github.com/filecoin-project/go-address"
	"golang.org/x/xerrors"
)

const (
	FILECOIN_EPOCH_DURATION   = 30
	GAME_CHAIN_EPOCH_LOOKBACK = 10
)

type GameVRF struct {
	rpcOptions []filrpc.Option

	lck             sync.Mutex
	isCacheValid    bool // use cache to reduce 'ChainHead' calls
	cachedEpoch     uint64
	cachedTimestamp time.Time
}

func New(options ...filrpc.Option) *GameVRF {
	return &GameVRF{
		rpcOptions: options,
	}
}

func (g *GameVRF) getTipsetByHeight(height uint64) (*filrpc.TipSet, error) {
	client := filrpc.New(g.rpcOptions...)

	for i := 0; i < GAME_CHAIN_EPOCH_LOOKBACK; i++ {
		tps, err := client.ChainGetTipSetByHeight(int64(height))
		if err != nil {
			return nil, err
		}

		if len(tps.Blocks()) > 0 {
			return tps, nil
		}
	}

	return nil, xerrors.Errorf("getTipsetByHeight can't found a non-empty tipset from height: %d", height)
}

func (g *GameVRF) getChainHead() (uint64, error) {
	client := filrpc.New(g.rpcOptions...)
	tps, err := client.ChainHead()
	if err != nil {
		return 0, xerrors.Errorf("getChainHead ChainHead call failed: %w", err)
	}

	return tps.Height(), nil
}

func (g *GameVRF) ForceUpdateCachedEpoch() (uint64, error) {
	g.lck.Lock()
	defer g.lck.Unlock()

	g.cachedTimestamp = time.Now()
	h, err := g.getChainHead()
	if err != nil {
		return 0, err
	}

	g.cachedEpoch = h
	g.isCacheValid = true

	return h, nil
}

func (g *GameVRF) getGameEpoch() (uint64, error) {
	g.lck.Lock()
	defer g.lck.Unlock()

	if !g.isCacheValid {
		g.cachedTimestamp = time.Now()
		h, err := g.getChainHead()
		if err != nil {
			return 0, err
		}

		g.cachedEpoch = h
		g.isCacheValid = true
	}

	duration := time.Since(g.cachedTimestamp)
	elapseEpoch := int64(duration.Seconds()) / FILECOIN_EPOCH_DURATION

	return g.cachedEpoch + uint64(elapseEpoch), nil
}

func (g *GameVRF) GenerateVRF(pers trand.DomainSeparationTag, filBlsPrivateKey []byte, entropy []byte) (*trand.VRFOut, error) {
	height, err := g.getGameEpoch()
	if err != nil {
		return nil, xerrors.Errorf("GenerateVRF getCachedHeight failed: %w", err)
	}

	if height <= GAME_CHAIN_EPOCH_LOOKBACK {
		return nil, xerrors.Errorf("GenerateVRF getCachedHeight return invalid height: %d", height)
	}

	lookback := height - GAME_CHAIN_EPOCH_LOOKBACK
	tps, err := g.getTipsetByHeight(lookback)
	if err != nil {
		return nil, xerrors.Errorf("GenerateVRF getTipsetByHeight failed: %w", err)
	}

	return trand.FilGenerateVRFByTipSet(pers, filBlsPrivateKey, tps, entropy)
}

func (g *GameVRF) VerifyVRF(pers trand.DomainSeparationTag, worker address.Address, entropy []byte, vrf *trand.VRFOut) error {
	tps, err := g.getTipsetByHeight(vrf.Height)
	if err != nil {
		return xerrors.Errorf("VerifyVRF getTipsetByHeight failed: %w", err)
	}

	return trand.FilVerifyVRFByTipSet(pers, worker, tps, entropy, vrf)
}
