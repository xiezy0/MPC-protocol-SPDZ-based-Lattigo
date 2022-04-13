package spdz2

import (
	"crypto/rand"
	"math"
	"math/big"
)

func rns(num int, encodeTriple *big.Int) (res *big.Int) {
	n := encodeTriple.BitLen()
	primeBit := evaPrimesBit(num)
	primeNumber := (n + primeBit - 1) * 2 / primeBit
	primeSlice, primeb := genPrimeSlice(primeNumber, primeBit)
	residuSlice := genResiduSlice(primeSlice, encodeTriple)
	res = crt(primeSlice, residuSlice, primeb)
	return
}

func rnsAddTest(num int, encodeTriple0 *big.Int, encodeTriple1 *big.Int) (res *big.Int) {
	n := encodeTriple0.BitLen()
	primeBit := evaPrimesBit(num)
	primeNumber := (n + primeBit - 1) * 2 / primeBit
	primeSlice, primeb := genPrimeSlice(primeNumber, primeBit)
	residuSlice0 := genResiduSlice(primeSlice, encodeTriple0)
	residuSlice1 := genResiduSlice(primeSlice, encodeTriple1)
	residuSliceAdd := rnsAdd(residuSlice0, residuSlice1, primeSlice)
	res = crt(primeSlice, residuSliceAdd, primeb)
	//fmt.Println("primeslice::", primeSlice)
	//fmt.Println("primeb::", primeb)
	//fmt.Println("residuslice::", residuSlice)
	//fmt.Println("eva::", res)
	return
}

func rnsMultTest(num int, encodeTriple0 *big.Int, encodeTriple1 *big.Int) (res *big.Int) {
	n := encodeTriple0.BitLen()
	primeBit := evaPrimesBit(num)
	primeNumber := (n + primeBit - 1) * 2 / primeBit
	primeSlice, primeb := genPrimeSlice(primeNumber, primeBit)
	residuSlice0 := genResiduSlice(primeSlice, encodeTriple0)
	residuSlice1 := genResiduSlice(primeSlice, encodeTriple1)
	residuSliceAdd := rnsMult(residuSlice0, residuSlice1, primeSlice)
	res = crt(primeSlice, residuSliceAdd, primeb)
	//fmt.Println("primeslice::", primeSlice)
	//fmt.Println("pri::", primeb)
	////fmt.Println("residuslice::", residuSlice)
	//fmt.Println("eva::", res)
	return
}

// 计算rns域中的加法
func rnsAdd(residuSlice0 []*big.Int, residuSlice1 []*big.Int, primeSlice []*big.Int) (residuSliceAdd []*big.Int) {
	residuSliceAdd = make([]*big.Int, 0)
	add := new(big.Int)
	for i, prime := range primeSlice {
		add.Add(residuSlice0[i], residuSlice1[i])
		residuSliceAdd = append(residuSliceAdd, new(big.Int).Mod(add, prime))
	}
	return
}

// 计算rns域中的乘法
func rnsMult(residuSlice0 []*big.Int, residuSlice1 []*big.Int, primeSlice []*big.Int) (residuSliceMult []*big.Int) {
	residuSliceMult = make([]*big.Int, 0)
	mul := new(big.Int)
	for i, prime := range primeSlice {
		mul.Mul(residuSlice0[i], residuSlice1[i])
		residuSliceMult = append(residuSliceMult, new(big.Int).Mod(mul, prime))
	}
	return
}

// 中国剩余定理解密
func crt(primesSlice []*big.Int, residuSlice []*big.Int, primeb *big.Int) (res *big.Int) {
	res = new(big.Int).SetInt64(0)
	primesSliceDiv := make([]*big.Int, 0)
	primesSliceDivInv := make([]*big.Int, 0)
	xj := make([]*big.Int, 0)
	mmi := new(big.Int)
	for _, prime := range primesSlice {
		primesSliceDiv = append(primesSliceDiv, new(big.Int).Div(primeb, prime))
	}
	// fmt.Println("primeslicediv::", primesSliceDiv)
	for i, prime := range primesSlice {
		primesSliceDivInv = append(primesSliceDivInv, new(big.Int).ModInverse(primesSliceDiv[i], prime))
	}
	// fmt.Println("primesSliceDivInv::", primesSliceDivInv)
	for i, primediv := range primesSliceDiv {
		mmi.Mul(primediv, primesSliceDivInv[i])
		mmi.Mod(mmi, primeb)
		xj = append(xj, new(big.Int).Mul(mmi, residuSlice[i]))
	}
	for _, xjj := range xj {
		res.Add(res, xjj)
		res.Mod(res, primeb)
	}
	return
}

// 计算剩余项
func genResiduSlice(primeSlice []*big.Int, encodeTriple *big.Int) (residuSlice []*big.Int) {
	residuSlice = make([]*big.Int, 0)
	for _, prime := range primeSlice {
		residuSlice = append(residuSlice, new(big.Int).Mod(encodeTriple, prime))
	}
	return
}

// 生成素数
func genPrimeSlice(primeNumber int, primeBit int) (primeSlice []*big.Int, primeb *big.Int) {
	primeb = big.NewInt(1)
	primeSlice = make([]*big.Int, 0)
	for i := 0; i < primeNumber; i++ {
		primel, _ := rand.Prime(rand.Reader, primeBit)
		if InSlice(primeSlice, primel) {
			i--
		} else {
			primeSlice = append(primeSlice, primel)
			primeb.Mul(primeb, primel)
		}
	}
	return
}

// 根据计算方数量 计算每一个小素数的位数
func evaPrimesBit(num int) (res int) {
	lognum := math.Log2(float64(num))
	res = 29 - int(lognum)
	return
}

// 元素item是否在切片items中
func InSlice(items []*big.Int, item *big.Int) bool {
	for _, eachItem := range items {
		if eachItem == item {
			return true
		}
	}
	return false
}
