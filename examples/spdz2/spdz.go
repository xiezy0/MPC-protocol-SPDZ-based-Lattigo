package spdz2

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strconv"
)

func spdz() {

}

func genTriple(num int) {
	fprime, _ := rand.Prime(rand.Reader, 64)
	trilpA, _ := rand.Int(rand.Reader, fprime)
	trilpB, _ := rand.Int(rand.Reader, fprime)
	tripleCright := new(big.Int).Mul(trilpA, trilpB)
	tripleAaBright := new(big.Int).Add(trilpA, trilpB)
	fmt.Println("trilpA", trilpA)
	fmt.Println("trilpB", trilpB)

	params := rnsInit(num, []*big.Int{trilpA, trilpB})
	residuSliceA := encodeBigUintSlice(params.genResiduSlice(trilpA))
	residuSliceB := encodeBigUintSlice(params.genResiduSlice(trilpB))

	publicparams, P := dkeyGen(num)
	ciphertext0 := publicparams.bfvEnc(residuSliceA)
	ciphertext1 := publicparams.bfvEnc(residuSliceB)
	ciphertext2 := publicparams.bfvAdd(ciphertext0, ciphertext1)
	ciphertext3 := publicparams.bfvMult(ciphertext0, ciphertext1)
	ciphertext2New := publicparams.keyswitch(ciphertext2, P)
	ciphertext3New := publicparams.keyswitch(ciphertext3, P)
	plaintext2 := publicparams.bfvDDec(ciphertext2New)
	plaintext3 := publicparams.bfvDDec(ciphertext3New)

	res0 := params.crt(decodeUintBigSlice(plaintext2))
	res1 := params.crt(decodeUintBigSlice(plaintext3))

	fmt.Println("trilpCright", tripleCright)
	fmt.Println("trilpCevalu", res1)
	fmt.Println("tripleAaBright", tripleAaBright)
	fmt.Println("tripleAaBevalu", res0)
}

func encodeBigUintSlice(plaintextBigSlice []*big.Int) (plaintextUintSlice []uint64) {
	plaintextUintSlice = make([]uint64, 0)
	for _, plaintextBig := range plaintextBigSlice {
		plaintextUintSlice = append(plaintextUintSlice, encodeBigUint(plaintextBig))
	}
	return
}

func decodeUintBigSlice(plaintextUintSlice []uint64) (plaintextBigSlice []*big.Int) {
	plaintextBigSlice = make([]*big.Int, 0)
	for _, plaintextUint := range plaintextUintSlice {
		plaintextBigSlice = append(plaintextBigSlice, decodeUintBig(plaintextUint))
	}
	return
}

func encodeBigUint(plaintextBig *big.Int) (plaintextUint uint64) {
	plaintextUint, erro := strconv.ParseUint(plaintextBig.String(), 10, 64)
	if erro != nil {
		panic(erro)
	}
	return
}

func decodeUintBig(plaintextUint uint64) (plaintextBig *big.Int) {
	return new(big.Int).SetUint64(plaintextUint)
}
