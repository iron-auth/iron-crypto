package encryption

import (
	"crypto/hmac"
	"crypto/sha256"

	"github.com/iron-auth/iron-crypto/ironerrors"
	"github.com/iron-auth/iron-crypto/key"
	"github.com/iron-auth/iron-crypto/str"
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
		return HmacData{}, ironerrors.ErrInvalidHmacAlgorithm
	}
}

func sha256Hmac(k key.GeneratedKey, message string) (HmacData, error) {
	mac := hmac.New(sha256.New, k.Key)

	if _, err := mac.Write(str.ToBuffer(message)); err != nil {
		return HmacData{}, ironerrors.ErrWritingHmac
	}

	return HmacData{
		Digest: str.ToBase64(mac.Sum(nil)),
		Salt:   k.Salt,
	}, nil
}
