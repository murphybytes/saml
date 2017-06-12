package saml

import (
	"encoding/base64"
	"encoding/xml"
	"net/url"
	"testing"
	"time"

	"github.com/Watchbeam/clock"
	"github.com/murphybytes/saml/generated"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetBindingLocation(t *testing.T) {
	supported := []SingleSignOnService{
		SingleSignOnService{
			Binding:  redirectBinding,
			Location: "https://myidp.com/redirect",
		},
		SingleSignOnService{
			Binding:  postBinding,
			Location: "https://myidp.com/post",
		},
	}

	location, err := getSSOBindingLocation(redirectBinding, supported)
	require.Nil(t, err)
	assert.Equal(t, "https://myidp.com/redirect", location)

	_, err = getSSOBindingLocation(soapBinding, supported)
	require.NotNil(t, err)
	assert.Equal(t, ErrBindingNotSupported, err)

}

func TestRedirectBinding(t *testing.T) {
	buff, err := generated.Asset("test_data/metadata.xml")
	require.Nil(t, err)
	require.NotNil(t, buff)

	var entity EntityDescriptor
	err = xml.Unmarshal(buff, &entity)
	require.Nil(t, err)

	sp := &ServiceProvider{
		IssuerURI: "uri:myserviceprovider",
		NameIDFormats: []string{
			NameIDEmail,
		},
	}

	provider := NewSingleSignOnProfile(sp, &entity.IDPSSODescriptor)

	binding, err := provider.RedirectBinding()
	assert.Nil(t, err)
	assert.NotEqual(t, "", binding)
}

func TestRedirectBindingWithRelayState(t *testing.T) {
	buff, err := generated.Asset("test_data/metadata.xml")
	require.Nil(t, err)
	require.NotNil(t, buff)

	var entity EntityDescriptor
	err = xml.Unmarshal(buff, &entity)
	require.Nil(t, err)

	sp := &ServiceProvider{
		IssuerURI: "uri:myserviceprovider",
		NameIDFormats: []string{
			NameIDEmail,
		},
	}

	provider := NewSingleSignOnProfile(sp, &entity.IDPSSODescriptor)
	// Use optional parameter to pass relay state
	binding, err := provider.RedirectBinding(RelayState("foobar"))
	assert.Nil(t, err)
	assert.NotEqual(t, "", binding)
	assert.Contains(t, binding, "foobar")
}

func getFormAuthResponse(t *testing.T) string {
	rawResponse, err := generated.Asset("test_data/authresponse")
	require.Nil(t, err)
	unencoded, err := url.QueryUnescape(string(rawResponse))
	require.Nil(t, err)
	return unencoded
}

func getMockProvider(t *testing.T) *SingleSignOnProfile {
	metadata, err := generated.Asset("test_data/metadata.xml")
	require.Nil(t, err)
	var entity EntityDescriptor
	err = xml.Unmarshal(metadata, &entity)
	require.Nil(t, err)
	sp := &ServiceProvider{
		IssuerURI: "uri:myserviceprovider",
		NameIDFormats: []string{
			NameIDEmail,
		},
	}
	return NewSingleSignOnProfile(sp, &entity.IDPSSODescriptor)
}

func TestPostBindingResponse(t *testing.T) {
	unencoded := getFormAuthResponse(t)
	buff, err := generated.Asset("test_data/metadata.xml")
	require.Nil(t, err)
	var entity EntityDescriptor
	err = xml.Unmarshal(buff, &entity)
	require.Nil(t, err)
	sp := &ServiceProvider{
		IssuerURI: "uri:myserviceprovider",
		NameIDFormats: []string{
			NameIDEmail,
		},
	}
	provider := NewSingleSignOnProfile(sp, &entity.IDPSSODescriptor)
	requestInstant := clock.NewMockClock(time.Date(2017, 5, 29, 0, 6, 0, 0, time.UTC))
	identity, err := provider.HandlePostResponse(unencoded, requestInstant.Now())
	require.Nil(t, err)
	require.NotNil(t, identity)
	assert.Equal(t, "john@kolide.co", identity.UserID)
}

func TestSignatureValidation(t *testing.T) {
	unencoded := getFormAuthResponse(t)
	provider := getMockProvider(t)
	decoded, err := base64.StdEncoding.DecodeString(unencoded)
	require.Nil(t, err)
	doc, err := provider.validateSignature(decoded)
	assert.Nil(t, err)
	assert.NotNil(t, doc)
}

func TestGetValidationContext(t *testing.T) {
	provider := getMockProvider(t)
	context, err := provider.getValidationContext()
	require.Nil(t, err)
	assert.NotNil(t, context)
}

func TestDecodeAuthResponse(t *testing.T) {
	unencoded := getFormAuthResponse(t)
	response, err := decodeAuthResponse(unencoded)
	require.Nil(t, err)
	assert.Equal(t, "R22cb13db51b271e2df86f6b2933a75229498a979", response.ID)
}
