package spdz2

import (
	"crypto/rand"
	"fmt"
	"github.com/ldsec/lattigo/v2/bfv"
	"math/big"
	"strconv"
	"sync"
	"sync/atomic"
)

// the public params of SPDZ
type spdzParams struct {
	rnsparams    rnsParams
	publicparams PublicParams
	fprime       *big.Int
}

func spdzInit(num int, security int) (params rnsParams, fprime *big.Int) {
	params = rnspdzInit(num, 64)
	fprime, _ = rand.Prime(rand.Reader, 64)
	return
}

func GenTriple(num int) {
	skChan := make(chan *party, num)
	rnsparams, fprime := spdzInit(num, 64)
	publicparams, P := dkeyGen(num)
	spdzparams := spdzParams{rnsparams, publicparams, fprime}
	//wgmain, _, _, _ := encTxInit(num)
	//wgmain1, _, _, _ := encTxInit(num)
	wgmain, mutex, encch, queuelen := encTxInit(num)
	wgmain1, mutex1, encch1, queuelen1 := encTxInit(num)
	_, mutex2, encch2, queuelen2 := encTxInit(num)
	wgmain3, mutex3, encch3, queuelen3 := encTxInit(num)
	trilpAlpha, _ := rand.Int(rand.Reader, fprime)
	ciphertextAlpha := publicparams.bfvEnc(encodeBigUintSlice(rnsparams.genResiduSlice(trilpAlpha)))
	fmt.Println(trilpAlpha)
	mutexSwitch := sync.Mutex{}
	for i := 0; i < num; i++ {
		skChan <- P[i]
	}
	//bigone  := new(big.Int).SetInt64(1)
	//bigzero := new(big.Int).SetInt64(0)
	// num goroutine <---> num players
	for i := 0; i < num; i++ {
		go func(params spdzParams, Id int, convSyncChan0 <-chan *party) {
			trilpa, _ := rand.Int(rand.Reader, params.fprime)
			trilpb, _ := rand.Int(rand.Reader, params.fprime)
			f, _ := rand.Int(rand.Reader, params.fprime)
			fmt.Println(f)
			//psk := <-convSyncChan0
			//fmt.Println(psk)
			mutexSwitch.Lock()
			ciphertexta := params.publicparams.bfvEnc(encodeBigUintSlice(params.rnsparams.genResiduSlice(trilpa)))
			ciphertextb := params.publicparams.bfvEnc(encodeBigUintSlice(params.rnsparams.genResiduSlice(trilpb)))
			ciphertextf := params.publicparams.bfvEnc(encodeBigUintSlice(params.rnsparams.genResiduSlice(f)))
			mutexSwitch.Unlock()
			//
			ciphertextaSlice := encTx(&mutex, encch, Id, num, queuelen, ciphertexta)
			ciphertextbSlice := encTx(&mutex1, encch1, Id, num, queuelen1, ciphertextb)
			ciphertextfSlice := encTx(&mutex2, encch2, Id, num, queuelen2, ciphertextf)
			// fmt.Println("goroutine", Id, ":", ciphertextaSlice, ciphertextbSlice)

			ciphertextA := publicparams.eval1Phase(1, ciphertextaSlice)
			ciphertextB := publicparams.eval1Phase(1, ciphertextbSlice)
			ciphertextF := publicparams.eval1Phase(1, ciphertextfSlice)

			ciphertextCold := publicparams.bfvMult(ciphertextA, ciphertextB)
			ciphertextCShareold := publicparams.bfvAdd(ciphertextCold, ciphertextF)

			mutexSwitch.Lock()
			plaintextCshare := new(big.Int)
			if Id == 0 {
				ciphertextCshare := params.publicparams.keyswitch(publicparams.bfvSub(ciphertextCShareold, ciphertextf), P)
				plaintextCshare = params.rnsparams.crt(decodeUintBigSlice(params.publicparams.bfvDDec(ciphertextCshare)))

			} else {
				plaintextCshare = f
			}
			mutexSwitch.Unlock()

			wgmain1.Done()
			wgmain1.Wait()

			mutexSwitch.Lock()
			fmt.Println("player", Id, "share C:", plaintextCshare)
			bigzero := new(big.Int).SetInt64(0)
			ciphertextcnew := params.publicparams.bfvEnc(encodeBigUintSlice(params.rnsparams.genResiduSlice(plaintextCshare)))
			ciphertextCnew := params.publicparams.bfvEnc(encodeBigUintSlice(params.rnsparams.genResiduSlice(bigzero)))
			mutexSwitch.Unlock()

			ciphertextcSlice := encTx(&mutex3, encch3, Id, num, queuelen3, ciphertextcnew)
			wgmain3.Done()
			wgmain3.Wait()

			for _, ciphertext := range ciphertextcSlice {
				ciphertextCnew = publicparams.bfvAdd(ciphertextCnew, ciphertext)
			}
			ciphertextCnewAlpha := publicparams.bfvMult(ciphertextCnew, ciphertextAlpha)
			ciphertextCnewAlphashare := publicparams.bfvAdd(ciphertextCnewAlpha, ciphertextF)

			//39748363081423454926855472378417859248
			//96392199965515998152829273534692535360
			mutexSwitch.Lock()
			plaintextCalphashare := new(big.Int)
			if Id == 0 {
				ciphertextswitch := publicparams.bfvSub(ciphertextCnewAlphashare, ciphertextf)
				ciphertextAnew := params.publicparams.keyswitch(ciphertextswitch, P)
				plaintextCalphashare = params.rnsparams.crt(decodeUintBigSlice(params.publicparams.bfvDDec(ciphertextAnew)))
			} else {
				plaintextCalphashare = f
			}
			fmt.Println("player", Id, "share C alpha:", plaintextCalphashare)
			mutexSwitch.Unlock()

			wgmain.Done()
		}(spdzparams, i, skChan)
	}
	fmt.Println(rnsparams.primeb)
	// 4224251410346486574217241457275025533307997891809872903980948405892929
	// 221045479695725508474707326942100346508 997525690921640950
	wgmain.Wait()
	close(skChan)
	//time.Sleep(time.Second * 4)  3343168732

}

func encTxInit(players int) (wgmain sync.WaitGroup, mutex sync.Mutex, ch chan *bfv.Ciphertext, queuelen uint64) {
	wgmain = sync.WaitGroup{}
	wgmain.Add(players)
	mutex = sync.Mutex{}
	ch = make(chan *bfv.Ciphertext, players)
	queuelen = uint64(0)
	return
}

func encTx(mutex *sync.Mutex, ch chan *bfv.Ciphertext, num int, players int, queuelen uint64, enc *bfv.Ciphertext) (m []*bfv.Ciphertext) {
	m = make([]*bfv.Ciphertext, players)
	ch <- enc
LABEL:
	mutex.Lock()
	if atomic.StoreUint64(&queuelen, uint64(len(ch))); atomic.CompareAndSwapUint64(&queuelen, uint64(players), 0) {
		for j := 0; j < players; j++ {
			m[j] = <-ch
		}
		for j := 0; j < players; j++ {
			ch <- m[j]
		}
		mutex.Unlock()
	} else {
		mutex.Unlock()
		goto LABEL
	}
	return
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

	publicparams, P := dkeyGen(num)
	ciphertext0 := publicparams.bfvEnc(encodeBigUintSlice(params.genResiduSlice(trilpA)))
	ciphertext1 := publicparams.bfvEnc(encodeBigUintSlice(params.genResiduSlice(trilpB)))
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
