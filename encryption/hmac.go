package encryption

import (
	"crypto/hmac"
	"crypto/sha256"

	"github.com/iron-auth/iron-crypto/ironerrors"
	"github.com/iron-auth/iron-crypto/key"
	"github.com/iron-auth/iron-crypto/str"
	"github.com/james-elicx/go-utils/utils"
)

// Data returned from a HMAC operation.
type HmacData struct {
	// Base64 encoded HMAC.
	Digest string
	// The key's salt.
	Salt string
}

// Generate a HMAC digest for the given message.
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

	_, err := mac.Write(str.ToBuffer(message))

	return HmacData{
		Digest: str.ToBase64(mac.Sum(nil)),
		Salt:   k.Salt,
	}, utils.Ternary(err != nil, ironerrors.ErrWritingHmac, nil)
}
