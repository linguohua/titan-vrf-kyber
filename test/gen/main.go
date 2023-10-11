package main

import (
	"fmt"
	"os"
	"titan-vrf/test"

	cborgen "github.com/whyrusleeping/cbor-gen"
)

func main() {
	err := cborgen.WriteMapEncodersToFile("cbor_gen.go", "test", test.GameRoundInfo{})
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
