package encryption

import (
	"crypto/aes"
	"crypto/cipher"

	"github.com/iron-auth/iron-tokens"
	"github.com/iron-auth/iron-tokens/utils/bits"
	"github.com/iron-auth/iron-tokens/utils/key"
	"github.com/iron-auth/iron-tokens/utils/str"
)

type EncryptedData struct {
	Encrypted []byte
	Key       key.GeneratedKey
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
		return EncryptedData{}, iron.ErrInvalidEncryptionAlgorithm
	}
}

func aes256cbcEncrypt(k key.GeneratedKey, message string) (EncryptedData, error) {
	block, err := aes.NewCipher(k.Key)
	if err != nil {
		return EncryptedData{}, iron.ErrCreatingCipher
	}

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
	block, err := aes.NewCipher(k.Key)
	if err != nil {
		return EncryptedData{}, iron.ErrCreatingCipher
	}

	plainText := str.ToBuffer(message)
	cipherText := str.MakeBuffer(len(plainText))

	mode := cipher.NewCFBEncrypter(block, k.IV)
	mode.XORKeyStream(cipherText, plainText)

	return EncryptedData{
		Encrypted: cipherText,
		Key:       k,
	}, nil
}
