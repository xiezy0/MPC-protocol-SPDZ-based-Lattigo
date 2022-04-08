package main

import (
	"fmt"
	"github.com/ldsec/lattigo/v2/bfv"
	"github.com/ldsec/lattigo/v2/rlwe"
)

func encdec() {
	// 参数选择
	paramDef := bfv.PN13QP218
	paramDef.T = 0x3ee0001
	params, err := bfv.NewParametersFromLiteral(paramDef)
	if err != nil {
		panic(err)
	}

	// 密钥初始化
	kgen := bfv.NewKeyGenerator(params)
	Sk, Pk := kgen.GenKeyPair()
	rlk := kgen.GenRelinearizationKey(Sk, 2)

	// 编码器
	encoder := bfv.NewEncoder(params)
	// 加密 解密 同态计算
	encryptor := bfv.NewEncryptor(params, Pk)
	evaluator := bfv.NewEvaluator(params, rlwe.EvaluationKey{Rlk: rlk})
	decryptor := bfv.NewDecryptor(params, Sk)

	// 加密1302*171
	data1 := make([]int64, 1)
	for i := 0; i < 1; i++ {
		data1[i] = 5
	}
	data2 := make([]int64, 1)
	for i := 0; i < 1; i++ {
		data2[i] = 8
	}
	plaintext1 := bfv.NewPlaintext(params)
	encoder.EncodeInt(data1, plaintext1) //将data1编码为int64的明文plaintext1
	plaintext2 := bfv.NewPlaintext(params)
	encoder.EncodeInt(data2, plaintext2) //将data2编码为int64的明文plaintext2

	ciphertext1 := encryptor.EncryptNew(plaintext1)
	ciphertext2 := encryptor.EncryptNew(plaintext2)

	//使用Evaluator 对密文进行乘法、再线性化计算以及解密。
	plaintext4 := decryptor.DecryptNew(evaluator.MulNew(ciphertext1, ciphertext2))

	// 结果输出
	var result []int64
	result = encoder.DecodeIntNew(plaintext4)
	fmt.Println("8与5实现加密，同态乘法，解密")
	fmt.Println(result[0])
}

func encdecdis() {
	// 参数选择
	paramDef := bfv.PN13QP218
	paramDef.T = 0x3ee0001
	params, err := bfv.NewParametersFromLiteral(paramDef)
	if err != nil {
		panic(err)
	}

	// 密钥初始化
	kgen := bfv.NewKeyGenerator(params)
	sk0, sk1, sk, pk := kgen.GenKeyPairDis()
	rlk := kgen.GenRelinearizationKey(sk, 2)

	// 编码器
	encoder := bfv.NewEncoder(params)

	// p0,p1 加密，同态计算器
	encryptor := bfv.NewEncryptor(params, pk)
	evaluator := bfv.NewEvaluator(params, rlwe.EvaluationKey{Rlk: rlk})
	// p0解密器
	_ = bfv.NewDecryptor(params, sk0)
	// p1解密器
	decryptor1 := bfv.NewDecryptor(params, sk1)
	// 正确的解密
	decryptor := bfv.NewDecryptor(params, sk)

	// 加密5*8
	data1 := make([]int64, 1)
	for i := 0; i < 1; i++ {
		data1[i] = 5
	}
	data2 := make([]int64, 1)
	for i := 0; i < 1; i++ {
		data2[i] = 8
	}
	plaintext1 := bfv.NewPlaintext(params)
	encoder.EncodeInt(data1, plaintext1) //将data1编码为int64的明文plaintext1
	plaintext2 := bfv.NewPlaintext(params)
	encoder.EncodeInt(data2, plaintext2) //将data2编码为int64的明文plaintext2

	ciphertext1 := encryptor.EncryptNew(plaintext1)
	ciphertext2 := encryptor.EncryptNew(plaintext2)

	// p0 解密
	decplaintext0 := decryptor.DecryptNew(evaluator.MulNew(ciphertext1, ciphertext2))
	// p1 解密
	_ = decryptor1.DecryptNew(evaluator.MulNew(ciphertext1, ciphertext2))

	var result0 []int64
	result0 = encoder.DecodeIntNew(decplaintext0)
	fmt.Println("8与5实现加密，同态乘法，p0解密")
	fmt.Println(result0[0])

	//var result1 []int64
	//result1 = encoder.DecodeIntNew(decplaintext1)
	//fmt.Println("8与5实现加密，同态乘法，p0解密")
	//fmt.Println(result1)
}

func main() {
	encdecdis()
	//encdec()
}
