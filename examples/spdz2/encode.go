package spdz2

import (
	"math"
	"math/big"
)

func Encode1(valueSlice []*big.Int, m int) (encodeValue *big.Int) {
	num := len(valueSlice)
	encodeValue = new(big.Int).SetUint64(0)
	for i, value := range valueSlice {
		// 2^(i-1) - 1
		exp2i_1_1 := new(big.Int).SetInt64(int64(math.Exp2(float64(i)) - 1))
		// d = m + log2(num) + 1
		d := m + int(math.Log2(float64(num))) + 1
		// k = d + m
		k := new(big.Int).SetInt64(int64(d + m))
		// k * (2^(i-1) - 1)
		kexp2i_1_1 := new(big.Int).Mul(exp2i_1_1, k)
		// 2 ^ (k * (2^(i-1) - 1))
		encodebase := new(big.Int).Exp(new(big.Int).SetInt64(2), kexp2i_1_1, nil)
		// value * 2 ^ (k * (2^(i-1) - 1))
		encodevalue := new(big.Int).Mul(encodebase, value)
		encodeValue.Add(encodeValue, encodevalue)
	}
	return
}

func Decode1(encodeValue *big.Int, num, m int) (valueSlice []*big.Int) {
	valueSlice = make([]*big.Int, 0)
	for i := num; i > 0; i-- {
		// 2^(i-1) - 1
		exp2i_1_1 := new(big.Int).SetInt64(int64(math.Exp2(float64(i-1)) - 1))
		// d = m + log2(num) + 1
		d := m + int(math.Log2(float64(num))) + 1
		// k = d + m
		k := new(big.Int).SetInt64(int64(d + m))
		// k * (2^(i-1) - 1)
		kexp2i_1_1 := new(big.Int).Mul(exp2i_1_1, k)
		// 2 ^ (k * (2^(i-1) - 1))
		encodebase := new(big.Int).Exp(new(big.Int).SetInt64(2), kexp2i_1_1, nil)
		value := new(big.Int).Div(encodeValue, encodebase)
		encodeValue.Mod(encodeValue, encodebase)
		valueSlice = append(valueSlice, value)
	}
	valueSlice = rev(valueSlice)
	return
}

func Encode2(valueSlice []*big.Int, m int) (encodeValue *big.Int) {
	num := len(valueSlice)
	encodeValue = new(big.Int).SetUint64(0)
	for i, value := range valueSlice {
		// 2 *（2^(i-1) - 1）
		exp2i_1_1 := new(big.Int).SetInt64(int64(math.Exp2(float64(i))-1) * 2)
		// d = m + log2(num) + 1
		d := m + int(math.Log2(float64(num))) + 1
		// k = d + m
		k := new(big.Int).SetInt64(int64(d + m))
		// 2 * k * (2^(i-1) - 1)
		kexp2i_1_1 := new(big.Int).Mul(exp2i_1_1, k)
		// 2 ^ (2 * k * (2^(i-1) - 1))
		encodebase := new(big.Int).Exp(new(big.Int).SetInt64(2), kexp2i_1_1, nil)
		// value * 2 ^ (2 * k * (2^(i-1) - 1))
		encodevalue := new(big.Int).Mul(encodebase, value)
		encodeValue.Add(encodeValue, encodevalue)
	}
	return
}

func Decode2(encodeValue *big.Int, num, m int) (valueSlice []*big.Int) {
	valueSlice = make([]*big.Int, 0)
	for i := num; i > 0; i-- {
		// 2 *（2^(i-1) - 1）
		exp2i_1_1 := new(big.Int).SetInt64(int64(math.Exp2(float64(i-1))-1) * 2)
		// d = m + log2(num) + 1
		d := m + int(math.Log2(float64(num))) + 1
		// k = d + m
		k := new(big.Int).SetInt64(int64(d + m))
		// 2 * k * (2^(i-1) - 1)
		kexp2i_1_1 := new(big.Int).Mul(exp2i_1_1, k)
		// 2 ^ (2 * k * (2^(i-1) - 1))
		encodebase := new(big.Int).Exp(new(big.Int).SetInt64(2), kexp2i_1_1, nil)
		value := new(big.Int).Div(encodeValue, encodebase)
		encodeValue.Mod(encodeValue, encodebase)
		valueSlice = append(valueSlice, value)
	}
	valueSlice = rev(valueSlice)
	return
}

func rev(slice []*big.Int) []*big.Int {
	for i, j := 0, len(slice)-1; i < j; i, j = i+1, j-1 {
		slice[i], slice[j] = slice[j], slice[i]
	}
	return slice
}
