package iron_test

import (
	"strings"
	"testing"

	"github.com/iron-auth/iron-crypto"
	"github.com/iron-auth/iron-crypto/ironerrors"
	"github.com/iron-auth/iron-crypto/key"
	"github.com/iron-auth/iron-crypto/pw"
	a "github.com/james-elicx/go-utils/assert"
)

func TestSeal(t *testing.T) {
	t.Parallel()

	sealed, err := iron.Seal(DecryptedMessage, pw.Raw{
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

	a.Equals(t, len(strings.Split(sealed, "*")), 8)
	a.Equals(t, len(strings.Split(sealed, "*")), len(strings.Split(SealedFromNode, "*")))
}

func TestSealFailWithInvalidObject(t *testing.T) {
	t.Parallel()

	sealed, err := iron.Seal(make(chan int), pw.Raw{
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

	a.Equals(t, err, ironerrors.ErrMarshallingObject)
	a.Equals(t, sealed, "")
}

func TestSealFailWithInvalidPassword(t *testing.T) {
	t.Parallel()

	sealed, err := iron.Seal(DecryptedMessage, pw.Raw{
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
	a.Equals(t, sealed, "")
}

func TestSealFailWithInvalidAlgo(t *testing.T) {
	t.Parallel()

	sealed, err := iron.Seal(DecryptedMessage, pw.Raw{
		Password: pw.Password{
			String: DecryptedPassword,
		},
	}, iron.SealConfig{
		Encryption: iron.SealConfigOptions{
			Algorithm:         key.SHA256,
			Iterations:        2,
			MinPasswordLength: 32,
			SaltBits:          256,
		},
		Integrity:           SealIntegrity,
		TTL:                 0,
		TimestampSkewSec:    0,
		LocalTimeOffsetMsec: 0,
	})

	a.Equals(t, err, ironerrors.ErrInvalidEncryptionAlgorithm)
	a.Equals(t, sealed, "")
}
