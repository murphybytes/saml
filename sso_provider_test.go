package saml

import (
	"encoding/xml"
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

func TestNewRedirectBinding(t *testing.T) {
	buff, err := generated.Asset("test_data/metadata.xml")
	require.Nil(t, err)
	require.NotNil(t, buff)

	var entity EntityDescriptor
	err = xml.Unmarshal(buff, &entity)
	require.Nil(t, err)

	sp := &ServiceProvider{
		IssuerURI: "uri:myserviceprovider",
		NameIDFormats: []string{
			nameIDEmail,
		},
	}

	provider := NewSSOProvider(sp, &entity.IDPSSODescriptor)

	binding, err := provider.RedirectBinding()
	assert.Nil(t, err)
	assert.NotEqual(t, "", binding)
}
