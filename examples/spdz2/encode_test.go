package spdz2

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"
)

func TestEncode(t *testing.T) {
	t.Run("testEncode1", func(t *testing.T) {
		prime, _ := rand.Prime(rand.Reader, 32)
		value0Slice := make([]*big.Int, 0)
		value1Slice := make([]*big.Int, 0)
		valueSliceAddRight := make([]*big.Int, 0)
		for i := 0; i < 8; i++ {
			value0, _ := rand.Int(rand.Reader, prime)
			value1, _ := rand.Int(rand.Reader, prime)
			value0Slice = append(value0Slice, value0)
			value1Slice = append(value1Slice, value1)
			valueSliceAddRight = append(valueSliceAddRight, new(big.Int).Add(value0, value1))
		}
		fmt.Println("value0Slice:", value0Slice)
		fmt.Println("value0Slice:", value1Slice)
		encodevalue0 := Encode1(value0Slice, 32)
		encodevalue1 := Encode1(value1Slice, 32)
		decodeaddSlice := Decode1(new(big.Int).Add(encodevalue0, encodevalue1), 8, 32)
		fmt.Println("addright:", valueSliceAddRight)
		fmt.Println("addevalu:", decodeaddSlice)
	})
	t.Run("testEncode2", func(t *testing.T) {
		prime, _ := rand.Prime(rand.Reader, 32)
		value0Slice := make([]*big.Int, 0)
		value1Slice := make([]*big.Int, 0)
		valueSliceAddRight := make([]*big.Int, 0)
		for i := 0; i < 8; i++ {
			value0, _ := rand.Int(rand.Reader, prime)
			value1, _ := rand.Int(rand.Reader, prime)
			value0Slice = append(value0Slice, value0)
			value1Slice = append(value1Slice, value1)
			valueSliceAddRight = append(valueSliceAddRight, new(big.Int).Add(value0, value1))
		}
		fmt.Println("value0Slice:", value0Slice)
		fmt.Println("value0Slice:", value1Slice)
		encodevalue0 := Encode2(value0Slice, 32)
		encodevalue1 := Encode2(value1Slice, 32)
		decodeaddSlice := Decode2(new(big.Int).Add(encodevalue0, encodevalue1), 8, 32)
		fmt.Println("addright:", valueSliceAddRight)
		fmt.Println("addevalu:", decodeaddSlice)
	})
	t.Run("testEncode12", func(t *testing.T) {
		prime, _ := rand.Prime(rand.Reader, 32)
		value0Slice := make([]*big.Int, 0)
		value1Slice := make([]*big.Int, 0)
		valueSliceMultRight := make([]*big.Int, 0)
		for i := 0; i < 8; i++ {
			value0, _ := rand.Int(rand.Reader, prime)
			value1, _ := rand.Int(rand.Reader, prime)
			value0Slice = append(value0Slice, value0)
			value1Slice = append(value1Slice, value1)
			valueSliceMultRight = append(valueSliceMultRight, new(big.Int).Mul(value0, value1))
		}
		fmt.Println("value0Slice:", value0Slice)
		fmt.Println("value0Slice:", value1Slice)

		encodevalue0 := Encode1(value0Slice, 32)
		encodevalue1 := Encode1(value1Slice, 32)
		// TODO: 增加二级解码的mod数选取
		decodemultSlice := Decode2(new(big.Int).Mul(encodevalue0, encodevalue1), 8, 32)
		fmt.Println("multright:", valueSliceMultRight)
		fmt.Println("multevalu:", decodemultSlice)
	})

}
