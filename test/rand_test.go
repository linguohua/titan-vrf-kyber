package test

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"titan-vrf/filrpc"
	"titan-vrf/gamevrf"
	"titan-vrf/trand"

	"github.com/filecoin-project/go-address"
)

var (
	chainHeight = int64(3290700)
	// filecoin bls private key
	filPrivateKey = []byte{152, 112, 35, 145, 21, 31, 99, 206, 204, 113, 33, 99, 241, 180, 157, 194, 91, 224, 34, 186, 137, 10, 136, 38, 133, 32, 109, 255, 59, 81, 45, 26}
	// filecoin bls public key
	filPublicKey = []byte{146, 209, 52, 147, 166, 127, 130, 148, 172, 13, 162, 254, 17, 85, 254, 151, 93, 182, 28, 218, 103, 106, 200, 115, 178, 101, 156, 74, 25, 214, 220, 136, 167, 32, 147, 231, 40, 250, 149, 109, 229, 58, 7, 135, 214, 93, 55, 169}

	filProof = []byte{142, 29, 17, 132, 11, 118, 73, 71, 12, 198, 33, 149, 65, 120, 199, 133, 42, 150, 253, 26, 238, 132, 72, 64, 121, 59, 223, 33, 43, 240, 87, 36, 27, 173, 38, 32, 118, 5, 64, 103, 240, 41, 18, 19, 63, 56, 18, 148, 0, 205, 78, 60, 62, 200, 153, 44, 145, 25, 29, 195, 25, 85, 190, 0, 210, 38, 250, 93, 114, 212, 205, 23, 85, 223, 204, 198, 215, 130, 196, 122, 38, 103, 91, 70, 166, 71, 228, 52, 80, 72, 102, 85, 140, 11, 233, 111}
)

func TestVRFGenVerify(t *testing.T) {
	nodeURL := "http://api.node.glif.io/rpc/v1"

	client := filrpc.New(
		filrpc.NodeURLOption(nodeURL),
	)

	tps, err := client.ChainGetTipSetByHeight(chainHeight)
	if err != nil {
		t.Fatal(err)
	}

	privateKey := filPrivateKey
	publicKey := filPublicKey

	var entropy []byte
	var gameRoundInfo = GameRoundInfo{
		GameID:    "abc-efg-hi",
		PlayerIDs: "a,b,c,d",
		RoundID:   "gogogogo1",
		ReplayID:  "bilibili",
	}

	buf := new(bytes.Buffer)
	err = gameRoundInfo.MarshalCBOR(buf)
	if err != nil {
		t.Fatal(err)
	}
	entropy = buf.Bytes()

	vrfout, err := gamevrf.FilGenerateVRFByTipSet(gamevrf.DomainSeparationTag_GameBasic, privateKey, tps, entropy)
	if err != nil {
		t.Fatal(err)
	}

	for i, p := range vrfout.Proof {
		if p != filProof[i] {
			t.Fatalf("proof not equal %d != %d, pos:%d", p, filProof[i], i)
		}
	}

	addr, err := address.NewBLSAddress(publicKey)
	if err != nil {
		t.Fatal(err)
	}

	err = gamevrf.FilVerifyVRFByTipSet(gamevrf.DomainSeparationTag_GameBasic, addr, tps, entropy, vrfout)
	if err != nil {
		t.Fatal(err)
	}
}

func TestVRFGenVerify2(t *testing.T) {
	nodeURL := "http://api.node.glif.io/rpc/v1"

	client := filrpc.New(
		filrpc.NodeURLOption(nodeURL),
	)

	tps, err := client.ChainGetTipSetByHeight(chainHeight)
	if err != nil {
		t.Fatal(err)
	}

	publicKey := filPublicKey

	var entropy []byte
	var gameRoundInfo = GameRoundInfo{
		GameID:    "abc-efg-hi",
		PlayerIDs: "a,b,c,d",
		RoundID:   "gogogogo1",
		ReplayID:  "bilibili",
	}

	buf := new(bytes.Buffer)
	err = gameRoundInfo.MarshalCBOR(buf)
	if err != nil {
		t.Fatal(err)
	}
	entropy = buf.Bytes()

	vrfout := &gamevrf.VRFOut{
		Height: uint64(chainHeight),
		Proof:  filProof,
	}

	addr, err := address.NewBLSAddress(publicKey)
	if err != nil {
		t.Fatal(err)
	}

	err = gamevrf.FilVerifyVRFByTipSet(gamevrf.DomainSeparationTag_GameBasic, addr, tps, entropy, vrfout)
	if err != nil {
		t.Fatal(err)
	}
}

func TestVRFGenVerify3(t *testing.T) {
	nodeURL := "http://api.node.glif.io/rpc/v1"

	gg := gamevrf.New(filrpc.NodeURLOption(nodeURL))

	privateKey := filPrivateKey
	publicKey := filPublicKey

	var entropy []byte
	var gameRoundInfo = GameRoundInfo{
		GameID:    "abc-efg-hi",
		PlayerIDs: "a,b,c,d",
		RoundID:   "gogogogo1",
		ReplayID:  "bilibili",
	}

	buf := new(bytes.Buffer)
	err := gameRoundInfo.MarshalCBOR(buf)
	if err != nil {
		t.Fatal(err)
	}
	entropy = buf.Bytes()

	vrfout, err := gg.GenerateVRF(gamevrf.DomainSeparationTag_GameBasic, privateKey, entropy)
	if err != nil {
		t.Fatal(err)
	}

	addr, err := address.NewBLSAddress(publicKey)
	if err != nil {
		t.Fatal(err)
	}

	err = gg.VerifyVRF(gamevrf.DomainSeparationTag_GameBasic, addr, entropy, vrfout)
	if err != nil {
		t.Fatal(err)
	}

	var sb strings.Builder
	rng := trand.NewRng(vrfout.Sum256(), trand.RNGType_Normal)
	for i := 0; i < 10; i++ {
		sb.WriteString(fmt.Sprintf("%d,", rng.Intn(100)))
	}
	t.Logf("RNGType_Normal: %s", sb.String())

	var sb2 strings.Builder
	rng2 := trand.NewRng(vrfout.Sum256(), trand.RNGType_Cipher)
	for i := 0; i < 10; i++ {
		sb2.WriteString(fmt.Sprintf("%d,", rng2.Intn(100)))
	}
	t.Logf("RNGType_Cipher: %s", sb2.String())
}
