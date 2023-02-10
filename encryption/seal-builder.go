package encryption

import (
	"crypto/subtle"
	"strconv"
	"strings"

	"github.com/iron-auth/iron-crypto/ironerrors"
	"github.com/iron-auth/iron-crypto/key"
	"github.com/iron-auth/iron-crypto/str"
	"github.com/james-elicx/go-utils/utils"
)

const (
	macPrefix string = "Fe26.2"
)

// Builder for creating and parsing seals.
type SealBuilder struct {
	Id         string
	Salt       string
	IV         string
	B64        string
	Expiration int64
	macSalt    string
	macDigest  string

	macBase string
	seal    string
}

// Retrieve the stored HMAC salt.
func (sb *SealBuilder) GetHmacSalt() string {
	return sb.macSalt
}

func (sb *SealBuilder) buildHmacBase() {
	exp := utils.Ternary(sb.Expiration > 0, strconv.FormatInt(sb.Expiration, 10), "")

	sb.macBase = macPrefix + "*" + sb.Id + "*" + sb.Salt + "*" + sb.IV + "*" + sb.B64 + "*" + exp
}

func (sb *SealBuilder) retrieveHmac(keyCfg key.Config) (HmacData, error) {
	sb.buildHmacBase()
	return HmacWithPassword(keyCfg, sb.macBase)
}

// Build a new seal.
func (sb SealBuilder) Build(keyCfg key.Config) (string, error) {
	mac, err := sb.retrieveHmac(keyCfg)
	if err != nil {
		return "", err
	}

	sb.macSalt = mac.Salt
	sb.macDigest = mac.Digest

	sb.seal = sb.macBase + "*" + sb.macSalt + "*" + sb.macDigest
	return sb.seal, nil
}

func (sb *SealBuilder) Parse(sealed string, now int64, timestampSkewSec int) error {
	parts := strings.Split(sealed, "*")
	if len(parts) != 8 {
		return ironerrors.ErrInvalidSeal
	}

	if parts[0] != macPrefix {
		return ironerrors.ErrInvalidSeal
	}

	sb.Id = parts[1]
	sb.Salt = parts[2]
	sb.IV = parts[3]
	sb.B64 = parts[4]

	if parts[5] != "" {
		exp, err := strconv.ParseInt(parts[5], 10, 64)
		if err != nil {
			return ironerrors.ErrInvalidSeal
		}

		skew := utils.Ternary(timestampSkewSec == 0, 60, utils.Ternary(timestampSkewSec == -1, 0, timestampSkewSec))
		if exp <= (now - int64(skew*1000)) {
			return ironerrors.ErrExpiredSeal
		}

		sb.Expiration = exp
	}

	sb.macSalt = parts[6]
	sb.macDigest = parts[7]

	return nil
}

// NOTE: We are favoring the use of the internal subtle module for constant time comparisons instead of the custom function used in the JS libraries.
//
// The following is the GO version of the JS implementation:
//
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

// Verify a seal.
func (sb SealBuilder) Verify(keyCfg key.Config) error {
	mac, err := sb.retrieveHmac(keyCfg)
	if err != nil {
		return err
	}

	if subtle.ConstantTimeCompare(str.ToBuffer(mac.Digest), str.ToBuffer(sb.macDigest)) == 0 {
		return ironerrors.ErrBadSealHmac
	}

	return nil
}
