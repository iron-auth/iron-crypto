package encryption_test

import (
	"strconv"
	"testing"
	"time"

	"github.com/iron-auth/iron-crypto/encryption"
	"github.com/iron-auth/iron-crypto/ironerrors"
	"github.com/iron-auth/iron-crypto/key"
	a "github.com/james-elicx/go-utils/assert"
)

func TestReturnsErrorForInvalidAlgo(t *testing.T) {
	t.Parallel()

	sb := encryption.SealBuilder{
		Id:         "id",
		Salt:       "salt",
		IV:         "iv",
		B64:        "b64",
		Expiration: 0,
	}
	_, err := sb.Build(key.Config{
		Password: DecryptedPassword,
		Options:  key.DefaultEncryption,
	})

	a.EqualsError(t, err, ironerrors.ErrInvalidHmacAlgorithm)
}

func TestBuild(t *testing.T) {
	t.Parallel()

	sb := encryption.SealBuilder{
		Id:         "id",
		Salt:       "salt",
		IV:         "iv",
		B64:        "b64",
		Expiration: 0,
	}
	_, err := sb.Build(key.Config{
		Password: DecryptedPassword,
		Options:  key.DefaultIntegrity,
	})

	a.EqualsError(t, err, nil)
}

func TestParseErrorsOnInvalidSeal(t *testing.T) {
	t.Parallel()

	sb := encryption.SealBuilder{}
	err := sb.Parse("invalid", time.Now().UnixMilli(), 0)

	a.EqualsError(t, err, ironerrors.ErrInvalidSeal)
}

func TestParseErrorsOnInvalidPrefix(t *testing.T) {
	t.Parallel()

	sb := encryption.SealBuilder{}
	err := sb.Parse("prefix*******", time.Now().UnixMilli(), 0)

	a.EqualsError(t, err, ironerrors.ErrInvalidSeal)
}

func TestParseErrorsOnInvalidTimestamp(t *testing.T) {
	t.Parallel()

	sb := encryption.SealBuilder{}
	err := sb.Parse("Fe26.2*id*salt*iv*b64*timestamp*macsalt*macdigest", time.Now().UnixMilli(), 0)

	a.EqualsError(t, err, ironerrors.ErrInvalidSeal)
}

func TestParseErrorsOnExpiredTimestamp(t *testing.T) {
	t.Parallel()

	sb := encryption.SealBuilder{}
	err := sb.Parse("Fe26.2*id*salt*iv*b64*1*macsalt*macdigest", time.Now().UnixMilli(), 0)

	a.EqualsError(t, err, ironerrors.ErrExpiredSeal)
}

func TestParseWorks(t *testing.T) {
	t.Parallel()

	exp := time.Now().UnixMilli() + 1

	sb := encryption.SealBuilder{}
	err := sb.Parse("Fe26.2*id*salt*iv*b64*"+strconv.FormatInt(exp, 10)+"*macsalt*macdigest", time.Now().UnixMilli(), 0)

	a.Equals(t, err, nil)

	a.Equals(t, sb.Id, "id")
	a.Equals(t, sb.Salt, "salt")
	a.Equals(t, sb.IV, "iv")
	a.Equals(t, sb.B64, "b64")
	a.Equals(t, sb.Expiration, exp)
}

// func fixedTimeComparison(oldDigest string, newDigest string) bool {
// 	a := newDigest
// 	b := oldDigest

// 	mismatch := utils.Ternary(len(a) == len(b), 0, 1)

// 	if mismatch == 1 {
// 		b = a
// 	}

// 	for i := 0; i < len(a); i++ {
// 		mismatch |= int(a[i]) ^ int(b[i])
// 	}

// 	return mismatch == 0
// }

// func TestConstantTimeComparison(t *testing.T) {
// 	t.Parallel()

// 	sb := encryption.SealBuilder{}
// 	sb.Parse("Fe26.2*id*salt*iv*b64*1*macsalt*macdigest", time.Now().UnixMilli(), 0)

// 	sb2 := encryption.SealBuilder{}
// 	sb2.Parse("Fe26.2*id*salt*iv*b64*1*macsalt*macdigest", time.Now().UnixMilli(), 0)

// 	fmt.Println(fixedTimeComparison(sb.GetHmacDigest(), sb2.GetHmacDigest()))

// 	a.Equals(t, fixedTimeComparison(sb.GetHmacDigest(), sb2.GetHmacDigest()), 1)
// }

func TestVerifyFailsRetrievingHmac(t *testing.T) {
	t.Parallel()

	sb := encryption.SealBuilder{}
	sb.Parse("Fe26.2*id*salt*iv*b64*1*macsalt*macdigest", time.Now().UnixMilli(), 0)

	err := sb.Verify(key.Config{
		Password: "",
		Options:  key.DefaultIntegrity,
	})

	a.Equals(t, err, ironerrors.ErrPasswordRequired)
}

func TestVerifyFailsTimeCompare(t *testing.T) {
	t.Parallel()

	sb := encryption.SealBuilder{}
	sb.Parse("Fe26.2*id*salt*iv*b64*1*macsalt*macdigest", time.Now().UnixMilli(), 0)

	err := sb.Verify(key.Config{
		Password: DecryptedPassword,
		Options:  key.DefaultIntegrity,
	})

	a.Equals(t, err, ironerrors.ErrBadSealHmac)
}

func TestVerifyFailsTimeCompareWithDifferentSalts(t *testing.T) {
	t.Parallel()

	sbb := encryption.SealBuilder{
		Id:         "id",
		Salt:       "salt",
		IV:         "iv",
		B64:        "b64",
		Expiration: time.Now().UnixMilli() + 100000,
	}
	built, err := sbb.Build(key.Config{
		Password: DecryptedPassword,
		Options:  key.DefaultIntegrity,
	})
	a.Equals(t, err, nil)

	sb := encryption.SealBuilder{}
	sb.Parse(built, time.Now().UnixMilli(), 0)

	err = sb.Verify(key.Config{
		Password: DecryptedPassword,
		Options: key.OptionsConfig{
			Algorithm:         key.SHA256,
			Iterations:        1,
			MinPasswordLength: 32,
			SaltBits:          256,
			Salt:              "random salt",
		},
	})

	a.Equals(t, err, ironerrors.ErrBadSealHmac)
}

func TestVerifySucceeds(t *testing.T) {
	t.Parallel()

	sbb := encryption.SealBuilder{
		Id:         "id",
		Salt:       "salt",
		IV:         "iv",
		B64:        "b64",
		Expiration: time.Now().UnixMilli() + 100000,
	}
	built, err := sbb.Build(key.Config{
		Password: DecryptedPassword,
		Options:  key.DefaultIntegrity,
	})
	a.Equals(t, err, nil)

	sb := encryption.SealBuilder{}
	sb.Parse(built, time.Now().UnixMilli(), 0)

	err = sb.Verify(key.Config{
		Password: DecryptedPassword,
		Options: key.OptionsConfig{
			Algorithm:         key.SHA256,
			Iterations:        1,
			MinPasswordLength: 32,
			SaltBits:          256,
			Salt:              sb.GetHmacSalt(),
		},
	})

	a.Equals(t, err, nil)
}
