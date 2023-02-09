package encryption

import (
	"crypto/hmac"
	"crypto/sha256"

	"github.com/iron-auth/iron-tokens"
	"github.com/iron-auth/iron-tokens/utils/key"
	"github.com/iron-auth/iron-tokens/utils/str"
)

type HmacData struct {
	Digest string
	Salt   string
}

func HmacWithPassword(cfg key.Config, message string) (HmacData, error) {
	k, err := key.Generate(cfg)
	if err != nil {
		return HmacData{}, err
	}

	switch cfg.Options.Algorithm {
	case key.SHA256:
		return sha256Hmac(k, message)
	default:
		return HmacData{}, iron.ErrInvalidHmacAlgorithm
	}
}

func sha256Hmac(k key.GeneratedKey, message string) (HmacData, error) {
	mac := hmac.New(sha256.New, k.Key)

	if _, err := mac.Write(str.ToBuffer(message)); err != nil {
		return HmacData{}, iron.ErrWritingHmac
	}

	return HmacData{
		Digest: str.ToBase64(mac.Sum(nil)),
		Salt:   k.Salt,
	}, nil
}
