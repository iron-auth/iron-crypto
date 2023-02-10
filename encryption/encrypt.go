package encryption

import (
	"crypto/aes"
	"crypto/cipher"

	"github.com/iron-auth/iron-crypto/bits"
	"github.com/iron-auth/iron-crypto/ironerrors"
	"github.com/iron-auth/iron-crypto/key"
	"github.com/iron-auth/iron-crypto/str"
)

// Data returned from an encryption operation.
type EncryptedData struct {
	// Encrypted data.
	Encrypted []byte
	// Generated encryption key.
	Key key.GeneratedKey
}

// Encrypt the given string according to the encryption config.
func Encrypt(cfg key.Config, message string) (EncryptedData, error) {
	k, err := key.Generate(cfg)
	if err != nil {
		return EncryptedData{}, err
	}

	switch cfg.Options.Algorithm {
	case key.AES256CBC:
		return aes256cbcEncrypt(k, message)
	case key.AES128CTR:
		return aes128ctrEncrypt(k, message)
	default:
		return EncryptedData{}, ironerrors.ErrInvalidEncryptionAlgorithm
	}
}

func aes256cbcEncrypt(k key.GeneratedKey, message string) (EncryptedData, error) {
	block, _ := aes.NewCipher(k.Key)

	plainText := bits.Pad(str.ToBuffer(message), aes.BlockSize)
	cipherText := str.MakeBuffer(len(plainText))

	mode := cipher.NewCBCEncrypter(block, k.IV)
	mode.CryptBlocks(cipherText, plainText)

	return EncryptedData{
		Encrypted: cipherText,
		Key:       k,
	}, nil
}

func aes128ctrEncrypt(k key.GeneratedKey, message string) (EncryptedData, error) {
	block, _ := aes.NewCipher(k.Key)

	plainText := str.ToBuffer(message)
	cipherText := str.MakeBuffer(len(plainText))

	mode := cipher.NewCFBEncrypter(block, k.IV)
	mode.XORKeyStream(cipherText, plainText)

	return EncryptedData{
		Encrypted: cipherText,
		Key:       k,
	}, nil
}
