package saml

import (
	"encoding/xml"
	"testing"

	"github.com/murphybytes/saml/generated"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLogoutRedirectBinding(t *testing.T) {
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
	profile := NewSingleLogOutProfile(sp, &entity)
	binding, err := profile.RedirectBinding("someone@acme.com")
	assert.Nil(t, err)
	assert.NotEqual(t, "", binding)

}

var logoutResponse = `
<samlp:LogoutResponse InResponseTo="saTmz9HA4d"
                      Version="2.0"
                      IssueInstant="2017-06-11T20:29:27Z"
                      xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                      ID="_96ba4530-3112-0135-d53d-0266e0985f15"
                      >
    <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://app.onelogin.com/saml/metadata/649458</saml:Issuer>
    <samlp:Status>
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" />
        <samlp:StatusMessage>Successfully logged out from service </samlp:StatusMessage>
    </samlp:Status>
</samlp:LogoutResponse>
`

var logoutRequest = `
<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                     xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                     ID="saTmz9HA4d"
                     IssueInstant="2017-06-11T20:29:27Z"
                     Version="2.0"
                     >
    <saml:Issuer>https://app.onelogin.com/saml/metadata/649458</saml:Issuer>
    <NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">john@kolide.co</NameID>
</samlp:LogoutRequest>
`

func TestGetIssuerFromLogout(t *testing.T) {
	resp, err := createLogout(logoutResponse)
	require.Nil(t, err)
	assert.IsType(t, &LogoutResponse{}, resp)

	resp, err = createLogout(logoutRequest)
	require.Nil(t, err)
	assert.IsType(t, &LogoutRequest{}, resp)

	_, err = createLogout("<garbage")
	assert.NotNil(t, err)
}
