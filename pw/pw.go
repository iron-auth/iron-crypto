package pw

import (
	"unicode"

	"github.com/iron-auth/iron-crypto/ironerrors"
)

type Password struct {
	String string
	Buffer []byte
}

type Secret struct {
	Id     string
	Secret Password
}

type Specific struct {
	Id         string
	Encryption Password
	Integrity  Password
}

type Raw struct {
	Password
	Secret
	Specific
}

type UnsealRaw struct {
	Password Password
	Map      map[string]Raw
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
