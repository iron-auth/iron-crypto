package encryption

import (
	"crypto/aes"
	"crypto/cipher"

	"github.com/iron-auth/iron-crypto/bits"
	"github.com/iron-auth/iron-crypto/ironerrors"
	"github.com/iron-auth/iron-crypto/key"
	"github.com/iron-auth/iron-crypto/str"
)

// Encrypt the given string according to the encryption config.
func Decrypt(cfg key.Config, cipherText []byte) (string, error) {
	k, err := key.Generate(cfg)
	if err != nil {
		return "", err
	}

	switch cfg.Options.Algorithm {
	case key.AES256CBC:
		return aes256cbcDecrypt(k, cipherText)
	case key.AES128CTR:
		return aes128ctrDecrypt(k, cipherText)
	default:
		return "", ironerrors.ErrInvalidEncryptionAlgorithm
	}
}

func aes256cbcDecrypt(k key.GeneratedKey, cipherText []byte) (string, error) {
	block, _ := aes.NewCipher(k.Key)

	plainText := str.MakeBuffer(len(cipherText))

	mode := cipher.NewCBCDecrypter(block, k.IV)
	mode.CryptBlocks(plainText, cipherText)

	return str.FromBuffer(bits.Unpad(plainText)), nil
}

func aes128ctrDecrypt(k key.GeneratedKey, cipherText []byte) (string, error) {
	block, _ := aes.NewCipher(k.Key)

	plainText := str.MakeBuffer(len(cipherText))

	mode := cipher.NewCFBDecrypter(block, k.IV)
	mode.XORKeyStream(plainText, cipherText)

	return str.FromBuffer(plainText), nil
}
