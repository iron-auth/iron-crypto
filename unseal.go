package iron

import (
	"time"

	"github.com/iron-auth/iron-crypto/encryption"
	"github.com/iron-auth/iron-crypto/key"
	"github.com/iron-auth/iron-crypto/pw"
	"github.com/iron-auth/iron-crypto/str"
)

func Unseal[T any](sealed string, password pw.UnsealRaw, cfg SealConfig) (T, error) {
	var obj T
	now := time.Now().UnixMilli() + int64(cfg.LocalTimeOffsetMsec)

	sb := encryption.SealBuilder{}
	sb.Parse(sealed, now, cfg.TimestampSkewSec)

	pass, err := pw.NormaliseUnseal(password, sb.Id)
	if err != nil {
		return obj, err
	}

	err = sb.Verify(key.Config{
		Password:       pass.Integrity.String,
		PasswordBuffer: pass.Integrity.Buffer,
		Options: key.OptionsConfig{
			Algorithm:         cfg.Integrity.Algorithm,
			Iterations:        cfg.Integrity.Iterations,
			MinPasswordLength: cfg.Integrity.MinPasswordLength,
			SaltBits:          cfg.Encryption.SaltBits,
			Salt:              sb.GetHmacSalt(),
		},
	})
	if err != nil {
		return obj, err
	}

	encrypted, err := str.FromBase64(sb.B64)
	if err != nil {
		return obj, err
	}
	ivBytes, err := str.FromBase64(sb.IV)
	if err != nil {
		return obj, err
	}

	decrypted, err := encryption.Decrypt(key.Config{
		Password:       pass.Encryption.String,
		PasswordBuffer: pass.Encryption.Buffer,
		Options: key.OptionsConfig{
			Algorithm:         cfg.Encryption.Algorithm,
			Iterations:        cfg.Encryption.Iterations,
			MinPasswordLength: cfg.Encryption.MinPasswordLength,
			SaltBits:          cfg.Encryption.SaltBits,
			Salt:              sb.Salt,
			IV:                ivBytes,
		},
	}, encrypted)
	if err != nil {
		return obj, err
	}

	obj, err = str.ToObject[T](decrypted)
	if err != nil {
		return obj, err
	}

	return obj, nil
}
