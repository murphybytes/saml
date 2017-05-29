package saml

import (
	"bytes"
	"compress/flate"
	"crypto/rand"
	"encoding/base64"

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

func deflate(inflated *bytes.Buffer) (string, error) {
	var deflated bytes.Buffer
	writer, err := flate.NewWriter(&deflated, flate.DefaultCompression)
	if err != nil {
		return "", err
	}
	defer writer.Close()
	_, err = writer.Write(inflated.Bytes())
	if err != nil {
		return "", err
	}
	writer.Flush()
	return base64.StdEncoding.EncodeToString(deflated.Bytes()), nil
}
