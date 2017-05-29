package saml

import (
	"encoding/xml"
	"net/url"
	"testing"

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

	location, err := getBindingLocation(redirectBinding, supported)
	require.Nil(t, err)
	assert.Equal(t, "https://myidp.com/redirect", location)

	_, err = getBindingLocation(soapBinding, supported)
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

	provider := NewSSOProvider(sp, &entity.IDPSSODescriptor)

	binding, err := provider.RedirectBinding()
	assert.Nil(t, err)
	assert.NotEqual(t, "", binding)
}

func getFormAuthResponse(t *testing.T) string {
	rawResponse, err := generated.Asset("test_data/authresponse")
	require.Nil(t, err)
	unencoded, err := url.QueryUnescape(string(rawResponse))
	require.Nil(t, err)
	return unencoded
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
	provider := NewSSOProvider(sp, &entity.IDPSSODescriptor)
	identity, err := provider.PostBindingResponse(unencoded)
	require.Nil(t, err)
	require.NotNil(t, identity)
	assert.Equal(t, "john@kolide.co", identity.UserID)
}

func TestDecodeAuthResponse(t *testing.T) {
	unencoded := getFormAuthResponse(t)
	response, err := decodeAuthResponse(unencoded)
	require.Nil(t, err)
	assert.Equal(t, "R22cb13db51b271e2df86f6b2933a75229498a979", response.ID)
}
