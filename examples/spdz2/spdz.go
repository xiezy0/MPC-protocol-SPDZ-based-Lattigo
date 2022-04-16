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

var ()

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
	wgmain, mutex, encch, queuelen := encTxInit(num)
	for i := 0; i < num; i++ {
		skChan <- P[i]
	}
	// num goroutine <---> num players
	for i := 0; i < num; i++ {
		go func(params spdzParams, Id int, convSyncChan0 <-chan *party) {
			trilpa, _ := rand.Int(rand.Reader, fprime)
			//trilpb, _ := rand.Int(rand.Reader, fprime)
			psk := <-convSyncChan0
			fmt.Println(psk)
			residuSliceA := encodeBigUintSlice(params.rnsparams.genResiduSlice(trilpa))
			//residuSliceB := encodeBigUintSlice(params.rnsparams.genResiduSlice(trilpb))
			ciphertext0 := publicparams.bfvEnc(residuSliceA)
			//ciphertext1 := publicparams.bfvEnc(residuSliceB)
			for j := 0; j < num; j++ {
				ciphertext0Slice := encTx(&wgmain, &mutex, encch, Id, num, queuelen, ciphertext0)
				fmt.Println(ciphertext0Slice)
			}
		}(spdzparams, i, skChan)
	}
	close(skChan)
	wgmain.Wait()
}

func encTxInit(players int) (wgmain sync.WaitGroup, mutex sync.Mutex, ch chan *bfv.Ciphertext, queuelen uint64) {
	wgmain = sync.WaitGroup{}
	wgmain.Add(players)
	mutex = sync.Mutex{}
	ch = make(chan *bfv.Ciphertext, players)
	queuelen = uint64(0)
	return
}

func encTx(wgmain *sync.WaitGroup, mutex *sync.Mutex, ch chan *bfv.Ciphertext, num int, players int, queuelen uint64, enc *bfv.Ciphertext) (m []*bfv.Ciphertext) {
	m = make([]*bfv.Ciphertext, players)
	wg := sync.WaitGroup{}
	wg.Add(players)
	ch <- enc
LABEL:
	mutex.Lock()
	if atomic.StoreUint64(&queuelen, uint64(len(ch))); atomic.CompareAndSwapUint64(&queuelen, uint64(players), 0) {
		for j := 0; j < players; j++ {
			m[j] = <-ch
		}
		fmt.Println("goroutine", num, ":", m)
		wg.Done()
		for j := 0; j < players; j++ {
			ch <- m[j]
		}
		wgmain.Done()
		mutex.Unlock()
	} else {
		mutex.Unlock()
		goto LABEL
	}
	wg.Wait()
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
