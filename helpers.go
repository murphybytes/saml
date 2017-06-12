package saml

import (
	"bytes"
	"compress/flate"
	"crypto/rand"
	"encoding/base64"
	"encoding/xml"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/pkg/errors"
)

const (
	// ResponseQueryKey
	ResponseQueryKey   = "SAMLResponse"
	RequestQueryKey    = "SAMLRequest"
	RelayStateQueryKey = "RelayState"
	alphabet           = "abcdefghijklmnopqrstuvwzyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	idSize             = 10
)

type httpClientTimeout time.Duration

// WithTimeout pass an optional timeout to GetMetadataURL
func WithTimeout(timeout time.Duration) func() interface{} {
	return func() interface{} {
		return httpClientTimeout(timeout)
	}
}

// GetMetadataFromURL parses IDP metadata and returns an EntityDescriptor
func GetMetadataFromURL(url string, opts ...func() interface{}) (*EntityDescriptor, error) {
	var client http.Client
	for _, opt := range opts {
		switch t := opt().(type) {
		case httpClientTimeout:
			client.Timeout = time.Duration(t)
		}
	}
	resp, err := client.Get(url)
	if err != nil {
		return nil, errors.Wrap(err, "getting metadata")
	}
	defer resp.Body.Close()
	return getMetadata(resp.Body)
}

// GetMetadataFromFile parses IDP metadata stored in file.
func GetMetadataFromFile(metadataPath string) (*EntityDescriptor, error) {
	file, err := os.Open(metadataPath)
	if err != nil {
		return nil, errors.Wrap(err, "getting metadata")
	}
	defer file.Close()
	return getMetadata(file)
}

func getMetadata(reader io.Reader) (*EntityDescriptor, error) {
	var metadata EntityDescriptor
	err := xml.NewDecoder(reader).Decode(&metadata)
	if err != nil {
		return nil, errors.Wrap(err, "decoding metadata")
	}
	return &metadata, nil
}

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

func inflate(deflated string) (string, error) {
	unencoded, err := base64.StdEncoding.DecodeString(deflated)
	if err != nil {
		return "", errors.Wrap(err, "base 64 decode query")
	}

	reader := flate.NewReader(bytes.NewBuffer(unencoded))
	defer reader.Close()
	var inflated bytes.Buffer
	_, err = io.Copy(&inflated, reader)
	if err != nil {
		return "", errors.Wrap(err, "deflating response")
	}
	return inflated.String(), nil
}

func timestampValid(response *Response, thisInstant time.Time) (bool, error) {
	notOnOrAfter, err := time.Parse(time.RFC3339, response.Assertion.Conditions.NotOnOrAfter)
	if err != nil {
		return false, errors.Wrap(err, "validating response timestamp")
	}
	notBefore, err := time.Parse(time.RFC3339, response.Assertion.Conditions.NotBefore)
	if err != nil {
		return false, errors.Wrap(err, "validating response timestamp")
	}
	return thisInstant.After(notBefore) && thisInstant.Before(notOnOrAfter), nil
}
