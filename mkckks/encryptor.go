package mkckks

import (
	"github.com/ldsec/lattigo/v2/ckks"
)

// MKEncryptor is an interface wrapping the ckks.Encryptor with the ring used for encryption
type MKEncryptor interface {
	EncryptMK(plaintext *ckks.Plaintext) *MKCiphertext
}

// mkEncryptor is a struct wrapping the ckks.Encryptor with the ring used for encryption
type mkEncryptor struct {
	ckksEncryptor ckks.Encryptor
	peerID        uint64
	params        *ckks.Parameters
}

// NewMKEncryptor creates a new ckks encryptor fromm the given MKPublicKey and the ckks parameters
func NewMKEncryptor(pk *MKPublicKey, params *ckks.Parameters, id uint64) MKEncryptor {

	ckksPublicKey := new(ckks.PublicKey)
	ckksPublicKey.Value[0] = pk.key[0].poly[0] // b[0]
	ckksPublicKey.Value[1] = pk.key[1].poly[0] // a[0]

	return &mkEncryptor{ckks.NewEncryptorFromPk(params, ckksPublicKey), pk.peerID, params}
}

// EncryptMK encrypt the plaintext and put id in the ciphertext's peerIds
func (encryptor *mkEncryptor) EncryptMK(plaintext *ckks.Plaintext) *MKCiphertext {

	mkCiphertext := new(MKCiphertext)

	if encryptor.params.PiCount() != 0 {
		mkCiphertext.ciphertexts = encryptor.ckksEncryptor.EncryptNew(plaintext)
	} else {
		mkCiphertext.ciphertexts = encryptor.ckksEncryptor.EncryptFastNew(plaintext)
	}

	mkCiphertext.peerIDs = []uint64{encryptor.peerID}

	return mkCiphertext
}