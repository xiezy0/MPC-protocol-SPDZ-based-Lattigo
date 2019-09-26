package dbfv

import (
	"fmt"
	"github.com/ldsec/lattigo/bfv"
	"github.com/ldsec/lattigo/ring"
	"log"
	"testing"
)

func Test_DBFVScheme(t *testing.T) {

	paramSets := bfv.DefaultParams[0:1]
	bitDecomps := []uint64{60}
	nParties := []int{5}

	//sigmaSmudging := 6.36

	for _, params := range paramSets {

		// nParties data indpendant element
		bfvContext := bfv.NewBfvContext()
		if err := bfvContext.SetParameters(&params); err != nil {
			log.Fatal(err)
		}

		kgen := bfvContext.NewKeyGenerator()

		evaluator, err := bfvContext.NewEvaluator()
		if err != nil {
			log.Fatal(err)
		}

		context := bfvContext.ContextQ()

		contextT := bfvContext.ContextT()

		encoder := bfvContext.NewBatchEncoder()

		coeffsWant := contextT.NewUniformPoly()
		plaintextWant := bfvContext.NewPlaintext()
		encoder.EncodeUint(coeffsWant.Coeffs[0], plaintextWant)

		ciphertextTest := bfvContext.NewCiphertext(1)

		for _, parties := range nParties {

			crpGenerators := make([]*CRPGenerator, parties)
			for i := 0; i < parties; i++ {
				crpGenerators[i], err = NewCRPGenerator(nil, context)
				if err != nil {
					log.Fatal(err)
				}
				crpGenerators[i].Seed([]byte{})
			}

			// SecretKeys
			sk0_shards := make([]*bfv.SecretKey, parties)
			sk1_shards := make([]*bfv.SecretKey, parties)
			tmp0 := context.NewPoly()
			tmp1 := context.NewPoly()

			for i := 0; i < parties; i++ {
				sk0_shards[i], _ = kgen.NewSecretKey(1.0 / 3)
				sk1_shards[i], _ = kgen.NewSecretKey(1.0 / 3)
				context.Add(tmp0, sk0_shards[i].Get(), tmp0)
				context.Add(tmp1, sk1_shards[i].Get(), tmp1)
			}

			sk0 := new(bfv.SecretKey)
			sk1 := new(bfv.SecretKey)

			sk0.Set(tmp0)
			sk1.Set(tmp1)

			// Publickeys
			pk0, err := kgen.NewPublicKey(sk0)
			if err != nil {
				log.Fatal(err)
			}

			pk1, err := kgen.NewPublicKey(sk1)
			if err != nil {
				log.Fatal(err)
			}

			// Encryptors
			encryptor_pk0, err := bfvContext.NewEncryptor(pk0, nil)
			if err != nil {
				log.Fatal(err)
			}

			//encryptor_pk1, err := bfvContext.NewEncryptor(pk1)
			//if err != nil {
			//	log.Fatal(err)
			//}

			// Decryptors
			decryptor_sk0, err := bfvContext.NewDecryptor(sk0)
			if err != nil {
				log.Fatal(err)
			}

			decryptor_sk1, err := bfvContext.NewDecryptor(sk1)
			if err != nil {
				log.Fatal(err)
			}

			// Reference ciphertext
			ciphertext, err := encryptor_pk0.EncryptFromPkNew(plaintextWant)
			if err != nil {
				log.Fatal(err)
			}

			coeffsMul := contextT.NewPoly()
			for i := 0; i < 1; i++ {
				res, _ := evaluator.MulNew(ciphertext, ciphertext)
				ciphertext = res.Ciphertext()
				contextT.MulCoeffs(coeffsWant, coeffsWant, coeffsMul)
			}

			t.Run(fmt.Sprintf("N=%d/Qi=%dx%d/CRS_PRNG", context.N, len(context.Modulus), 60), func(t *testing.T) {

				Ha, _ := NewPRNG([]byte{})
				Hb, _ := NewPRNG([]byte{})

				// Random 32 byte seed
				seed1 := []byte{0x48, 0xc3, 0x31, 0x12, 0x74, 0x98, 0xd3, 0xf2,
					0x7b, 0x15, 0x15, 0x9b, 0x50, 0xc4, 0x9c, 0x00,
					0x7d, 0xa5, 0xea, 0x68, 0x1f, 0xed, 0x4f, 0x99,
					0x54, 0xc0, 0x52, 0xc0, 0x75, 0xff, 0xf7, 0x5c}

				// New reseed of the PRNG after one clock cycle with the seed1
				seed2 := []byte{250, 228, 6, 63, 97, 110, 68, 153,
					147, 236, 236, 37, 152, 89, 129, 32,
					185, 5, 221, 180, 160, 217, 247, 201,
					211, 188, 160, 163, 176, 83, 83, 138}

				Ha.Seed(seed1)
				Hb.Seed(append(seed1, seed2...)) //Append works since blake2b hashes blocks of 512 bytes

				Ha.SetClock(256)
				Hb.SetClock(255)

				a := Ha.Clock()
				b := Hb.Clock()

				for i := 0; i < 32; i++ {
					if a[i] != b[i] {
						t.Errorf("error : error prng")
						break
					}
				}

				crs_generator_1, _ := NewCRPGenerator(nil, context)
				crs_generator_2, _ := NewCRPGenerator(nil, context)

				crs_generator_1.Seed(seed1)
				crs_generator_2.Seed(append(seed1, seed2...)) //Append works since blake2b hashes blocks of 512 bytes

				crs_generator_1.SetClock(256)
				crs_generator_2.SetClock(255)

				p0 := crs_generator_1.Clock()
				p1 := crs_generator_2.Clock()

				if bfvContext.ContextQ().Equal(p0, p1) != true {
					t.Errorf("error : crs prng generator")
				}
			})

			// EKG_Naive
			for _, bitDecomp := range bitDecomps {

				t.Run(fmt.Sprintf("N=%d/Qi=%dx%d/bitdecomp=%d/EKG", context.N, len(context.Modulus), 60, bitDecomp), func(t *testing.T) {

					bitLog := uint64((60 + (60 % bitDecomp)) / bitDecomp)

					// Each party instantiate an ekg naive protocole
					ekg := make([]*RKGProtocol, parties)
					ephemeralKeys := make([]*ring.Poly, parties)

					crp := make([][]*ring.Poly, len(context.Modulus))
					for j := 0; j < len(context.Modulus); j++ {
						crp[j] = make([]*ring.Poly, bitLog)
						for u := uint64(0); u < bitLog; u++ {
							crp[j][u] = crpGenerators[0].Clock()
						}
					}

					for i := 0; i < parties; i++ {
						ekg[i] = NewEkgProtocol(bfvContext, bitDecomp)
						ephemeralKeys[i], _ = ekg[i].NewEphemeralKey(1.0 / 3)
					}

					rlk := test_EKG_Protocol(bfvContext, parties, bitDecomp, ekg, sk0_shards, ephemeralKeys, crp)

					if err := evaluator.Relinearize(ciphertext, rlk, ciphertextTest); err != nil {
						log.Fatal(err)
					}

					plaintextTest, err := decryptor_sk0.DecryptNew(ciphertextTest)
					if err != nil {
						log.Fatal(err)
					}

					coeffsTest, err := encoder.DecodeUint(plaintextTest)
					if err != nil {
						log.Fatal(err)
					}

					if equalslice(coeffsMul.Coeffs[0], coeffsTest) != true {
						t.Errorf("error : ekg rlk bad decrypt")
					}

				})
			}

			// EKG_Naive
			for _, bitDecomp := range bitDecomps {

				t.Run(fmt.Sprintf("N=%d/Qi=%dx%d/bitdecomp=%d/EKG_Naive", context.N, len(context.Modulus), 60, bitDecomp), func(t *testing.T) {

					// Each party instantiate an ekg naive protocole
					ekgNaive := make([]*EkgProtocolNaive, parties)
					for i := 0; i < parties; i++ {
						ekgNaive[i] = NewEkgProtocolNaive(context, bitDecomp)
					}

					evk := test_EKG_Protocol_Naive(parties, sk0_shards, pk0, ekgNaive)

					rlk := new(bfv.EvaluationKey)
					rlk.SetRelinKeys([][][][2]*ring.Poly{evk[0]}, bitDecomp)

					if err := evaluator.Relinearize(ciphertext, rlk, ciphertextTest); err != nil {
						log.Fatal(err)
					}

					plaintextTest, err := decryptor_sk0.DecryptNew(ciphertextTest)
					if err != nil {
						log.Fatal(err)
					}

					coeffsTest, err := encoder.DecodeUint(plaintextTest)
					if err != nil {
						log.Fatal(err)
					}

					if equalslice(coeffsMul.Coeffs[0], coeffsTest) != true {
						t.Errorf("error : ekg_naive rlk bad decrypt")
					}
				})
			}

			t.Run(fmt.Sprintf("N=%d/Qi=%dx%d/CKG", context.N, len(context.Modulus), 60), func(t *testing.T) {

				crp := crpGenerators[0].Clock()

				type Party struct {
					*CKGProtocol
					s  *ring.Poly
					s1 CKGShare
				}

				ckgParties := make([]*Party, parties)
				for i := 0; i < parties; i++ {
					p := new(Party)
					p.CKGProtocol = NewCKGProtocol(bfvContext)
					p.s = sk0_shards[i].Get()
					p.s1 = p.AllocateShares()
					ckgParties[i] = p
				}
				P0 := ckgParties[0]

				// Each party creates a new CKGProtocol instance
				for i, p := range ckgParties {
					p.GenShare(p.s, crp, p.s1)
					if i > 0 {
						P0.AggregateShares(p.s1, P0.s1, P0.s1)
					}
				}

				pk := &bfv.PublicKey{}
				P0.GenPublicKey(P0.s1, crp, pk)

				// Verifies that decrypt((encryptp(collectiveSk, m), collectivePk) = m
				encryptorTest, err := bfvContext.NewEncryptor(pk, nil)
				if err != nil {
					log.Fatal(err)
				}

				ciphertextTest, err := encryptorTest.EncryptFromPkNew(plaintextWant)

				if err != nil {
					log.Fatal(err)
				}

				plaintextTest, err := decryptor_sk0.DecryptNew(ciphertextTest)
				if err != nil {
					log.Fatal(err)
				}

				coeffsTest, err := encoder.DecodeUint(plaintextTest)
				if err != nil {
					log.Fatal(err)
				}

				if equalslice(coeffsWant.Coeffs[0], coeffsTest) != true {
					t.Errorf("error : ckg protocol, cpk encrypt/decrypt test")
				}

			})

			t.Run(fmt.Sprintf("N=%d/Qi=%dx%d/CKSProtocol", context.N, len(context.Modulus), 60), func(t *testing.T) {

				type Party struct {
					*CKSProtocol
					s0    *ring.Poly
					s1    *ring.Poly
					share CKSShare
				}

				cksParties := make([]*Party, parties)
				for i := 0; i < parties; i++ {
					p := new(Party)
					p.CKSProtocol = NewCKSProtocol(bfvContext, 6.36)
					p.s0 = sk0_shards[i].Get()
					p.s1 = sk1_shards[i].Get()
					p.share = p.AllocateShare()
					cksParties[i] = p
				}
				P0 := cksParties[0]

				ciphertext, err := encryptor_pk0.EncryptFromPkNew(plaintextWant)
				switchedCiphertext := bfvContext.NewCiphertext(1)
				if err != nil {
					log.Fatal(err)
				}

				// Each party creates its CKSProtocol instance with tmp = si-si'
				for i, p := range cksParties {
					p.GenShare(p.s0, p.s1, ciphertext, p.share)
					if i > 0 {
						P0.AggregateShares(p.share, P0.share, P0.share)
					}
				}

				P0.KeySwitch(P0.share, ciphertext, switchedCiphertext)

				plaintextHave, _ := decryptor_sk1.DecryptNew(switchedCiphertext)

				coeffsTest, err := encoder.DecodeUint(plaintextHave)
				if err != nil {
					log.Fatal(err)
				}

				if equalslice(coeffsWant.Coeffs[0], coeffsTest) != true {
					t.Errorf("error : decryption error")
				}
			})

			t.Run(fmt.Sprintf("N=%d/Qi=%dx%d/PCKS", context.N, len(context.Modulus), 60), func(t *testing.T) {

				type Party struct {
					*PCKSProtocol
					s     *ring.Poly
					share PCKSShare
				}

				pcksParties := make([]*Party, parties)
				for i := 0; i < parties; i++ {
					p := new(Party)
					p.PCKSProtocol = NewPCKSProtocol(bfvContext, 6.36)
					p.s = sk0_shards[i].Get()
					p.share = p.AllocateShares()
					pcksParties[i] = p
				}
				P0 := pcksParties[0]

				ciphertext, err := encryptor_pk0.EncryptFromPkNew(plaintextWant)
				ciphertextSwitched := bfvContext.NewCiphertext(1)
				if err != nil {
					log.Fatal(err)
				}

				for i, p := range pcksParties {
					p.GenShare(p.s, pk1, ciphertext, p.share)
					if i > 0 {
						P0.AggregateShares(p.share, P0.share, P0.share)
					}
				}

				P0.KeySwitch(P0.share, ciphertext, ciphertextSwitched)
				plaintextHave, _ := decryptor_sk1.DecryptNew(ciphertextSwitched)

				coeffsTest, err := encoder.DecodeUint(plaintextHave)
				if err != nil {
					log.Fatal(err)
				}

				if equalslice(coeffsWant.Coeffs[0], coeffsTest) != true {
					t.Errorf("error : PCKS")
				}
			})

			t.Run(fmt.Sprintf("N=%d/Qi=%dx%d/BOOT", context.N, len(context.Modulus), 60), func(t *testing.T) {

				ciphertext, err := encryptor_pk0.EncryptFromPkNew(plaintextWant)

				crp := crpGenerators[0].Clock()

				bootshares := make([]*BootShares, parties)

				for i := 0; i < parties; i++ {
					bootshares[i] = GenBootShares(sk0_shards[i], ciphertext, bfvContext, crp, encoder)
				}

				Bootstrapp(ciphertext, sk0.Get(), bootshares, bfvContext, crp, encoder)

				plaintextHave, _ := decryptor_sk0.DecryptNew(ciphertext)
				coeffsTest, err := encoder.DecodeUint(plaintextHave)
				if err != nil {
					log.Fatal(err)
				}

				if equalslice(coeffsWant.Coeffs[0], coeffsTest) != true {
					t.Errorf("error : BOOT")
				}
			})
		}
	}
}

func test_EKG_Protocol_Naive(parties int, sk []*bfv.SecretKey, collectivePk *bfv.PublicKey, ekgNaive []*EkgProtocolNaive) [][][][2]*ring.Poly {

	// ROUND 0
	// Each party generates its samples
	samples := make([][][][2]*ring.Poly, parties)
	for i := 0; i < parties; i++ {
		samples[i] = ekgNaive[i].GenSamples(sk[i].Get(), collectivePk.Get())
	}

	// ROUND 1
	// Each party aggretates its sample with the other n-1 samples
	aggregatedSamples := make([][][][2]*ring.Poly, parties)
	for i := 0; i < parties; i++ {
		aggregatedSamples[i] = ekgNaive[i].Aggregate(sk[i].Get(), collectivePk.Get(), samples)
	}

	// ROUND 2
	// Each party aggregates sums its aggregatedSample with the other n-1 aggregated samples
	evk := make([][][][2]*ring.Poly, parties)
	for i := 0; i < parties; i++ {
		evk[i] = ekgNaive[i].Finalize(aggregatedSamples)
	}

	return evk
}

func test_EKG_Protocol(bfvCtx *bfv.BfvContext, parties int, bitDecomp uint64, ekgProtocols []*RKGProtocol, sk []*bfv.SecretKey, ephemeralKeys []*ring.Poly, crp [][]*ring.Poly) *bfv.EvaluationKey {

	type Party struct {
		*RKGProtocol
		u      *ring.Poly
		s      *ring.Poly
		share1 RKGShareRoundOne
		share2 RKGShareRoundTwo
		share3 RKGShareRoundThree
	}

	rkgParties := make([]*Party, parties)

	for i := range rkgParties {
		p := new(Party)
		p.RKGProtocol = ekgProtocols[i]
		p.u = ephemeralKeys[i]
		p.s = sk[i].Get()
		p.share1, p.share2, p.share3 = p.RKGProtocol.AllocateShares()
		rkgParties[i] = p
	}

	P0 := rkgParties[0]

	// ROUND 1
	for i, p := range rkgParties {
		p.GenShareRoundOne(p.u, p.s, crp, p.share1)
		if i > 0 {
			P0.AggregateShareRoundOne(p.share1, P0.share1, P0.share1)
		}
	}

	//ROUND 2
	for i, p := range rkgParties {
		p.GenShareRoundTwo(P0.share1, p.s, crp, p.share2)
		if i > 0 {
			P0.AggregateShareRoundTwo(p.share2, P0.share2, P0.share2)
		}
	}

	// ROUND 3
	for i, p := range rkgParties {
		p.GenShareRoundThree(P0.share2, p.u, p.s, p.share3)
		if i > 0 {
			P0.AggregateShareRoundThree(p.share3, P0.share3, P0.share3)
		}
	}

	evk := bfvCtx.NewRelinKey(1, bitDecomp)
	P0.GenRelinearizationKey(P0.share2, P0.share3, evk)
	return evk
}
