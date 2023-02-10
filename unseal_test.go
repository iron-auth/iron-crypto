package iron_test

import (
	"testing"

	"github.com/iron-auth/iron-crypto"
	"github.com/iron-auth/iron-crypto/ironerrors"
	"github.com/iron-auth/iron-crypto/pw"
	a "github.com/james-elicx/go-utils/assert"
)

func TestUnsealFailsWithNoPassword(t *testing.T) {
	t.Parallel()

	_, err := iron.Unseal[string](SealedFromNode, pw.UnsealRaw{
		Password: pw.Password{
			String: "",
		},
	}, iron.SealConfig{
		Encryption:          SealEncryption,
		Integrity:           SealIntegrity,
		TTL:                 0,
		TimestampSkewSec:    0,
		LocalTimeOffsetMsec: 0,
	})

	a.Equals(t, err, ironerrors.ErrPasswordRequired)
}

func TestUnsealFailsWithInvalidSeal(t *testing.T) {
	t.Parallel()

	_, err := iron.Unseal[string]("", pw.UnsealRaw{
		Password: pw.Password{
			String: DecryptedPassword,
		},
	}, iron.SealConfig{
		Encryption:          SealEncryption,
		Integrity:           SealIntegrity,
		TTL:                 0,
		TimestampSkewSec:    0,
		LocalTimeOffsetMsec: 0,
	})

	a.Equals(t, err, ironerrors.ErrInvalidSeal)
}

func TestUnsealFailsWithInvalidJson(t *testing.T) {
	t.Parallel()

	_, err := iron.Unseal[string](InvalidJsonSealedFromGo, pw.UnsealRaw{
		Password: pw.Password{
			String: DecryptedPassword,
		},
	}, iron.SealConfig{
		Encryption:          SealEncryption,
		Integrity:           SealIntegrity,
		TTL:                 0,
		TimestampSkewSec:    0,
		LocalTimeOffsetMsec: 0,
	})

	a.Equals(t, err, ironerrors.ErrUnmarshallingObject)
}

func TestUnsealFailsWithInvalidB64(t *testing.T) {
	t.Parallel()

	_, err := iron.Unseal[string](InvalidB64SealedFromGo, pw.UnsealRaw{
		Password: pw.Password{
			String: DecryptedPassword,
		},
	}, iron.SealConfig{
		Encryption:          SealEncryption,
		Integrity:           SealIntegrity,
		TTL:                 0,
		TimestampSkewSec:    0,
		LocalTimeOffsetMsec: 0,
	})

	a.Equals(t, err, ironerrors.ErrBase64Decode)
}

func TestUnsealFailsWithInvalidIv(t *testing.T) {
	t.Parallel()

	_, err := iron.Unseal[string](InvalidIvSealedFromGo, pw.UnsealRaw{
		Password: pw.Password{
			String: DecryptedPassword,
		},
	}, iron.SealConfig{
		Encryption:          SealEncryption,
		Integrity:           SealIntegrity,
		TTL:                 0,
		TimestampSkewSec:    0,
		LocalTimeOffsetMsec: 0,
	})

	a.Equals(t, err, ironerrors.ErrBase64Decode)
}

func TestUnsealWorksWithValidJson(t *testing.T) {
	t.Parallel()

	obj, err := iron.Unseal[string](ValidJsonSealedFromGo, pw.UnsealRaw{
		Password: pw.Password{
			String: DecryptedPassword,
		},
	}, iron.SealConfig{
		Encryption:          SealEncryption,
		Integrity:           SealIntegrity,
		TTL:                 0,
		TimestampSkewSec:    0,
		LocalTimeOffsetMsec: 0,
	})

	a.Equals(t, err, nil)
	a.Equals(t, obj, DecryptedMessage)
}

func TestUnsealWorksWithNodeJSSeal(t *testing.T) {
	t.Parallel()

	obj, err := iron.Unseal[string](SealedFromNode, pw.UnsealRaw{
		Password: pw.Password{
			String: DecryptedPassword,
		},
	}, iron.SealConfig{
		Encryption:          SealEncryption,
		Integrity:           SealIntegrity,
		TTL:                 0,
		TimestampSkewSec:    0,
		LocalTimeOffsetMsec: 0,
	})

	a.Equals(t, err, nil)
	a.Equals(t, obj, DecryptedMessage)
}
