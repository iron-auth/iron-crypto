package pw

import (
	"unicode"

	"github.com/iron-auth/iron-crypto/ironerrors"
)

// A string or byte buffer that can be used as a password.
//
// Only supply one of the options.
type Password struct {
	// A string to use for the password.
	String string
	// A byte buffer to use for the password.
	Buffer []byte
}

// A password with an ID.
type Secret struct {
	// The ID of the password.
	Id string
	// The password.
	Secret Password
}

// A password with an ID and encryption and integrity passwords.
type Specific struct {
	// The ID of the password.
	Id string
	// The password to use for encryption.
	Encryption Password
	// The password to use for integrity.
	Integrity Password
}

// A password that can be a string/buffer, secret or specific.
//
// Only supply one of the options.
type Raw struct {
	// A string or byte buffer password.
	Password
	// A password with an ID.
	Secret
	// A password with an ID and encryption and integrity passwords.
	Specific
}

// A password that can be a string/buffer, or a map of password IDs to passwords.
type UnsealRaw struct {
	// A string or byte buffer password.
	Password Password
	// A map of password IDs to passwords that can be string/buffer, secret or specific.
	Map map[string]Raw
}

func normalisePassword(raw Raw) (Specific, error) {
	if raw.Password.String != "" || len(raw.Password.Buffer) != 0 {
		return Specific{
			Id:         "",
			Encryption: raw.Password,
			Integrity:  raw.Password,
		}, nil
	} else if raw.Secret.Secret.String != "" || len(raw.Secret.Secret.Buffer) != 0 {
		return Specific{
			Id:         raw.Secret.Id,
			Encryption: raw.Secret.Secret,
			Integrity:  raw.Secret.Secret,
		}, nil
	} else if (raw.Specific.Encryption.String != "" || len(raw.Specific.Encryption.Buffer) != 0) && (raw.Specific.Integrity.String != "" || len(raw.Specific.Integrity.Buffer) != 0) {
		return raw.Specific, nil
	}

	return Specific{}, ironerrors.ErrPasswordRequired
}
func isLettersOnly(s string) bool {
	for _, r := range s {
		if !unicode.IsLetter(r) {
			return false
		}
	}
	return true
}

func validatePassword(raw Specific) error {
	if raw.Id != "" && !isLettersOnly(raw.Id) {
		return ironerrors.ErrPasswordInvalid
	}

	return nil
}

// Normalise a password.
func Normalise(raw Raw) (Specific, error) {
	normalised, err := normalisePassword(raw)
	if err != nil {
		return Specific{}, err
	}

	if err = validatePassword(normalised); err != nil {
		return Specific{}, err
	}

	return normalised, nil
}

// Normalise an unseal password.
func NormaliseUnseal(raw UnsealRaw, passwordId string) (Specific, error) {
	if raw.Password.String == "" && len(raw.Password.Buffer) == 0 && len(raw.Map) == 0 {
		return Specific{}, ironerrors.ErrPasswordRequired
	}

	var foundPassword Raw

	if len(raw.Map) > 0 {
		var ok bool
		foundPassword, ok = raw.Map[passwordId]

		if !ok {
			foundPassword, ok = raw.Map["default"]
			if !ok {
				return Specific{}, ironerrors.ErrPasswordRequired
			}
		}
	} else {
		foundPassword = Raw{
			Password: raw.Password,
		}
	}

	normalised, err := Normalise(foundPassword)
	if err != nil {
		return Specific{}, err
	}

	return normalised, nil
}
