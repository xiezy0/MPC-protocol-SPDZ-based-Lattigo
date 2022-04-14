package spdz2

import (
	"fmt"
	"math/big"
	"testing"
)

func TestRnsgen(t *testing.T) {
	n0, _ := new(big.Int).SetString("10000000000000000000000000000000000000000000000000", 10)
	n1, _ := new(big.Int).SetString("10000000000000000000000000000000000000000000000000", 10)
	fmt.Println("n0:::::::", n0)
	fmt.Println("n1:::::::", n1)
	rnscom, _ := rns(4, n0)
	fmt.Println("commeva::", rnscom)
	rnsadd := rnsAddTest(4, n0, n1)
	fmt.Println("addeva:::", rnsadd)
	rnsmult := rnsMultTest(4, n0, n1)
	fmt.Println("multeva::", rnsmult)
}
