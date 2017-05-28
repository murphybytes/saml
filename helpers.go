package saml

import (
	"crypto/rand"

	"github.com/pkg/errors"
)

const alphabet = "abcdefghijklmnopqrstuvwzyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
const idSize = 10

func getUniqueID() (string, error) {
	buff := make([]byte, idSize)
	_, err := rand.Read(buff)
	if err != nil {
		return "", errors.Wrap(err, "getting unique id")
	}
	for i := 0; i < len(buff); i++ {
		buff[i] = alphabet[buff[i]%byte(len(alphabet))]
	}
	return string(buff), nil
}
