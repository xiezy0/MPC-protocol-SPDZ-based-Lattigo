package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/ldsec/lattigo/v2/bfv"
	"github.com/ldsec/lattigo/v2/dbfv"
	"github.com/ldsec/lattigo/v2/drlwe"
	ring "github.com/ldsec/lattigo/v2/ring"
	"github.com/ldsec/lattigo/v2/rlwe"
	"github.com/ldsec/lattigo/v2/utils"
	"math/big"
	"sync"
	"time"
	"unsafe"
)

type party struct {
	sk         *rlwe.SecretKey
	rlkEphemSk *rlwe.SecretKey

	ckgShare    *drlwe.CKGShare
	rkgShareOne *drlwe.RKGShare
	rkgShareTwo *drlwe.RKGShare
	pcksShare   *drlwe.PCKSShare

	input []uint64
}

type multTask struct {
	wg              *sync.WaitGroup
	op1             *bfv.Ciphertext
	op2             *bfv.Ciphertext
	res             *bfv.Ciphertext
	elapsedmultTask time.Duration
}

func dbfvTest() {
	N := 2
	// Creating encryption parameters from a default params with logN=14, logQP=438 with a plaintext modulus T=65537
	paramsDef := bfv.PN15QP827pq
	paramsDef.T = 576460752260694017
	params, err := bfv.NewParametersFromLiteral(paramsDef)
	if err != nil {
		panic(err)
	}

	crs, err := utils.NewKeyedPRNG([]byte{'s', 'p', 'd', 'z'})
	if err != nil {
		panic(err)
	}
	// 编码器
	encoder := bfv.NewEncoder(params)

	tsk, tpk := bfv.NewKeyGenerator(params).GenKeyPair()

	// Create each party, and allocate the memory for all the shares that the protocols will need
	// 给每个计算方创建一个私钥
	P := genparties(params, N)
	// Inputs & expected result
	expRes := genInputs(params, P)
	// 全局公钥创建 并共享公钥
	pk := ckgphase(params, crs, P)
	// 全局重线性化密钥创建
	rlk := rkgphase(params, crs, P)
	// 加密
	encInputs := encPhase(params, P, pk, encoder)
	//
	encRes := evalPhase(params, encInputs, rlk)
	encOut := pcksPhase(params, tpk, encRes, P)
	decryptor := bfv.NewDecryptor(params, tsk)
	ptres := bfv.NewPlaintext(params)
	decryptor.Decrypt(encOut, ptres)
	res := encoder.DecodeUintNew(ptres)
	fmt.Println("eva result", res[1])
	fmt.Println("right result", expRes[1])
}

func genparties(params bfv.Parameters, N int) []*party {

	// Create each party, and allocate the memory for all the shares that the protocols will need
	P := make([]*party, N)
	for i := range P {
		pi := &party{}
		pi.sk = bfv.NewKeyGenerator(params).GenSecretKey()
		P[i] = pi
	}

	return P
}

// 创建8×8
func genInputs(params bfv.Parameters, P []*party) (expRes []uint64) {
	expRes = make([]uint64, params.N())
	expRes[0] = 1
	expRes[1] = 1
	for _, pi := range P {
		pi.input = make([]uint64, params.N())
		pi.input[0] = 536870911
		//102232259
		pi.input[1] = 536870911
		expRes[0] *= pi.input[0]
		expRes[1] *= pi.input[1]
	}
	return
}

func BytesToString(data []byte) string {
	return *(*string)(unsafe.Pointer(&data))
}

func StringToBytes(data string) []byte {
	return *(*[]byte)(unsafe.Pointer(&data))
}

func encodeStringUint(plaintext string, params bfv.Parameters) []uint64 {
	enplaintext := make([]uint64, params.N())
	byplaintext := StringToBytes(plaintext)
	for i, elem := range byplaintext {
		enplaintext[i] = uint64(elem)
	}
	return enplaintext
}

func decodeUintString(deplaintext []uint64, params bfv.Parameters) (plaintext string) {
	buf := bytes.NewBuffer(make([]byte, 0))

	for _, elem := range deplaintext {
		binary.Write(buf, binary.BigEndian, uint64(elem))
	}

	return BytesToString(buf.Bytes())
}

func ckgphase(params bfv.Parameters, crs utils.PRNG, P []*party) *rlwe.PublicKey {

	ckg := dbfv.NewCKGProtocol(params) // Public key generation
	ckgCombined := ckg.AllocateShares()
	for _, pi := range P {
		pi.ckgShare = ckg.AllocateShares()
	}

	// 创建publickey的共享  p_i.sk * crp + e_i
	crp := ckg.SampleCRP(crs)
	for _, pi := range P {
		ckg.GenShare(pi.sk, crp, pi.ckgShare)
	}

	// 创建公钥b 将多方公钥的共享相加
	pk := bfv.NewPublicKey(params)
	for _, pi := range P {
		ckg.AggregateShares(pi.ckgShare, ckgCombined, ckgCombined)
	}
	// 格式化公钥 a, b
	ckg.GenPublicKey(ckgCombined, crp, pk)

	return pk
}

func rkgphase(params bfv.Parameters, crs utils.PRNG, P []*party) *rlwe.RelinearizationKey {

	rkg := dbfv.NewRKGProtocol(params) // Relineariation key generation
	_, rkgCombined1, rkgCombined2 := rkg.AllocateShares()

	for _, pi := range P {
		pi.rlkEphemSk, pi.rkgShareOne, pi.rkgShareTwo = rkg.AllocateShares()
	}
	crp := rkg.SampleCRP(crs)

	for _, pi := range P {
		rkg.GenShareRoundOne(pi.sk, crp, pi.rlkEphemSk, pi.rkgShareOne)
	}
	for _, pi := range P {
		rkg.AggregateShares(pi.rkgShareOne, rkgCombined1, rkgCombined1)
	}
	for _, pi := range P {
		rkg.GenShareRoundTwo(pi.rlkEphemSk, pi.sk, rkgCombined1, pi.rkgShareTwo)
	}
	rlk := bfv.NewRelinearizationKey(params, 1)
	for _, pi := range P {
		rkg.AggregateShares(pi.rkgShareTwo, rkgCombined2, rkgCombined2)
	}
	rkg.GenRelinearizationKey(rkgCombined1, rkgCombined2, rlk)

	return rlk
}

// 每个计算方生成自己输入文本的密文
func encPhase(params bfv.Parameters, P []*party, pk *rlwe.PublicKey, encoder bfv.Encoder) (encInputs []*bfv.Ciphertext) {
	encInputs = make([]*bfv.Ciphertext, len(P))
	for i := range encInputs {
		encInputs[i] = bfv.NewCiphertext(params, 1)
	}
	encryptor := bfv.NewEncryptor(params, pk)
	pt := bfv.NewPlaintext(params)
	for i, pi := range P {
		encoder.EncodeUint(pi.input, pt)
		encryptor.Encrypt(pt, encInputs[i])
	}
	return
}

func evalPhase(params bfv.Parameters, encInputs []*bfv.Ciphertext, rlk *rlwe.RelinearizationKey) (encRes *bfv.Ciphertext) {
	evaluator := bfv.NewEvaluator(params, rlwe.EvaluationKey{Rlk: rlk})
	cipertext0 := encInputs[0]
	for i := range encInputs {
		fmt.Println(i)
		if i != 0 {
			encRes = evaluator.MulNew(cipertext0, encInputs[i])
			evaluator.Relinearize(encRes, encRes) // 重线性化
		}
	}

	return
}

func eval1Phase(params bfv.Parameters, NGoRoutine int, encInputs []*bfv.Ciphertext, rlk *rlwe.RelinearizationKey) (encRes *bfv.Ciphertext) {

	encLvls := make([][]*bfv.Ciphertext, 0)
	encLvls = append(encLvls, encInputs)
	for nLvl := len(encInputs) / 2; nLvl > 0; nLvl = nLvl >> 1 {
		encLvl := make([]*bfv.Ciphertext, nLvl)
		for i := range encLvl {
			encLvl[i] = bfv.NewCiphertext(params, 2)
		}
		encLvls = append(encLvls, encLvl)
	}
	encRes = encLvls[len(encLvls)-1][0]

	evaluator := bfv.NewEvaluator(params, rlwe.EvaluationKey{Rlk: rlk, Rtks: nil})
	// Split the task among the Go routines
	tasks := make(chan *multTask)
	workers := &sync.WaitGroup{}
	workers.Add(NGoRoutine)
	//l.Println("> Spawning", NGoRoutine, "evaluator goroutine")
	for i := 1; i <= NGoRoutine; i++ {
		go func(i int) {
			evaluator := evaluator.ShallowCopy() // creates a shallow evaluator copy for this goroutine
			for task := range tasks {
				// 1) Multiplication of two input vectors
				evaluator.Mul(task.op1, task.op2, task.res)
				// 2) Relinearization
				evaluator.Relinearize(task.res, task.res)
				task.wg.Done()
			}
			//l.Println("\t evaluator", i, "down")
			workers.Done()
		}(i)
		//l.Println("\t evaluator", i, "started")
	}

	// Start the tasks
	for i, lvl := range encLvls[:len(encLvls)-1] {
		nextLvl := encLvls[i+1]
		wg := &sync.WaitGroup{}
		wg.Add(len(nextLvl))
		// 每两对并行处理密文
		for j, nextLvlCt := range nextLvl {
			task := multTask{wg, lvl[2*j], lvl[2*j+1], nextLvlCt, 0}
			tasks <- &task
		}
		wg.Wait()
	}
	//l.Println("> Shutting down workers")
	close(tasks)
	workers.Wait()

	return
}

func pcksPhase(params bfv.Parameters, tpk *rlwe.PublicKey, encRes *bfv.Ciphertext, P []*party) (encOut *bfv.Ciphertext) {
	// Collective key switching from the collective secret key to
	// the target public key

	pcks := dbfv.NewPCKSProtocol(params, 3.19)

	for _, pi := range P {
		pi.pcksShare = pcks.AllocateShareBFV()
	}

	for _, pi := range P {
		pcks.GenShare(pi.sk, tpk, encRes.Ciphertext, pi.pcksShare)
	}

	pcksCombined := pcks.AllocateShareBFV()
	encOut = bfv.NewCiphertext(params, 1)
	for _, pi := range P {
		pcks.AggregateShares(pi.pcksShare, pcksCombined, pcksCombined)
	}
	pcks.KeySwitch(pcksCombined, encRes.Ciphertext, encOut.Ciphertext)

	return

}

func getPrime() (p *big.Int) {
	paramsDef := bfv.PN15QP827pq
	primes := ring.GenerateNTTPrimes(59, 65536, 56)
	for _, prime := range primes {
		paramsDef.T = prime
		_, err := bfv.NewParametersFromLiteral(paramsDef)
		if err == nil {
			fmt.Println(prime)
		}
	}
	return
}

//576460752301785089
func main() {
	dbfvTest()

}
