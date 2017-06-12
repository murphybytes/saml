package saml

import (
	"bytes"
	"encoding/xml"
	"testing"

	"github.com/murphybytes/saml/generated"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEntityDescriptor(t *testing.T) {
	buff, err := generated.Asset("test_data/metadata.xml")
	require.Nil(t, err)
	require.NotNil(t, buff)
	var descriptor EntityDescriptor
	err = xml.Unmarshal(buff, &descriptor)
	require.Nil(t, err)

	require.Len(t, descriptor.IDPSSODescriptor.KeyDescriptors, 1)
	keyDescriptor := descriptor.IDPSSODescriptor.KeyDescriptors[0]
	assert.Equal(t, "signing", keyDescriptor.Use)
	expected := "MIIEFDCCAvygAw"
	require.True(t, len(keyDescriptor.KeyInfo.X509Data.X509Certificate.Data) > len(expected))
	assert.Equal(t, "MIIEFDCCAvygAw", keyDescriptor.KeyInfo.X509Data.X509Certificate.Data[:len(expected)])
	assert.Len(t, descriptor.IDPSSODescriptor.SingleSignOnService, 3)
	assert.Len(t, descriptor.IDPSSODescriptor.SingleLogoutService, 1)
}

func TestEntityDescriptorNoSingleLogout(t *testing.T) {
	buff, err := generated.Asset("test_data/metadata_noslo.xml")
	require.Nil(t, err)
	require.NotNil(t, buff)
	var descriptor EntityDescriptor
	err = xml.Unmarshal(buff, &descriptor)
	require.Nil(t, err)

	require.Len(t, descriptor.IDPSSODescriptor.KeyDescriptors, 1)
	keyDescriptor := descriptor.IDPSSODescriptor.KeyDescriptors[0]
	assert.Equal(t, "signing", keyDescriptor.Use)
	expected := "MIIEFDCCAvygAw"
	require.True(t, len(keyDescriptor.KeyInfo.X509Data.X509Certificate.Data) > len(expected))
	assert.Equal(t, "MIIEFDCCAvygAw", keyDescriptor.KeyInfo.X509Data.X509Certificate.Data[:len(expected)])
	assert.Len(t, descriptor.IDPSSODescriptor.SingleSignOnService, 3)
	assert.Len(t, descriptor.IDPSSODescriptor.SingleLogoutService, 0)
}

func TestLogoutRequest(t *testing.T) {

	var lr LogoutRequest
	lr.XMLName.Local = "samlp:LogoutRequest"
	lr.XMLName.Space = samlNamespace
	lr.SAMLP = samlProtocalNamespace
	lr.ID = "234"
	lr.NameID.Format = NameIDEmail
	lr.NameID.Value = "john@kolide.co"
	lr.Version = samlVersion
	var buff bytes.Buffer
	err := xml.NewEncoder(&buff).Encode(&lr)
	require.Nil(t, err)
	var decoded LogoutRequest

	err = xml.NewDecoder(&buff).Decode(&decoded)
	require.Nil(t, err)
	assert.Equal(t, lr.ID, decoded.ID)
}
