package saml

import (
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
}
