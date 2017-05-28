package saml

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"encoding/xml"
	"net/url"
	"time"

	"github.com/pkg/errors"
)

var (
	// ErrBindingNotSupported occurs when the SP binding is not supported by the IDP
	ErrBindingNotSupported = errors.New("binding not supported by IDP")
)

// ServiceProvider describes this service provider and various attributes
// that is supports.
type ServiceProvider struct {
	// IssuerURI uniquely identifies this type of service provider to the IDP
	IssuerURI string
	// NameIDFormats are the identifiers the service provider expects when checking if
	// the user ID returned in an AuthnResponse is known to this SP
	NameIDFormats []string
	// AssertionConsumerServiceURL is the URL of the service provider handler for
	// the AuthnResponse sent by the IDP after sign on.
	AssertionConsumerServiceURL string
}

// SSOProvider supplies single sign on functionality
type SSOProvider struct {
	serviceProvder *ServiceProvider
	idpDescription *IDPSSODescriptor
	relayState     string
}

// NewSSOProvider creates an SSOProvider
func NewSSOProvider(spDescription *ServiceProvider, idpDescription *IDPSSODescriptor) *SSOProvider {
	return &SSOProvider{
		serviceProvder: spDescription,
		idpDescription: idpDescription,
	}
}

// RedirectBinding returns a url suitable for use to satisfy the SAML
// redirect binding.
// See http://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf Section 3.4
func (sp *SSOProvider) RedirectBinding() (string, error) {
	idpRedirectURL, err := getBindingLocation(redirectBinding, sp.idpDescription.SingleSignOnService)
	if err != nil {
		return "", err
	}
	requestID, err := getUniqueID()
	if err != nil {
		return "", errors.Wrap(err, "getting id for redirect binding")
	}

	request := AuthnRequest{
		XMLName: xml.Name{
			Local: "samlp:AuthnRequest",
		},
		ID:    requestID,
		SAMLP: samlProtocalNamespace,
		SAML:  samlNamespace,
		AssertionConsumerServiceURL: sp.serviceProvder.AssertionConsumerServiceURL,
		Destination:                 idpRedirectURL,
		IssueInstant:                time.Now().UTC().Format(samlTimeFormat),
		ProtocolBinding:             redirectBinding,
		Version:                     samlVersion,
		Issuer: Issuer{
			XMLName: xml.Name{
				Local: "saml:Issuer",
			},
			Url: sp.serviceProvder.IssuerURI,
		},
	}

	idpURL, err := url.Parse(idpRedirectURL)
	if err != nil {
		return "", errors.Wrap(err, "parsing IDP URL")
	}
	urlQuery := idpURL.Query()
	var encodedRequest bytes.Buffer
	err = xml.NewEncoder(&encodedRequest).Encode(request)
	if err != nil {
		return "", errors.Wrap(err, "encoding auth request")
	}
	authQueryVal, err := deflate(&encodedRequest)
	if err != nil {
		return "", errors.Wrap(err, "compressing auth request")
	}
	urlQuery.Set("SAMLRequest", authQueryVal)
	if sp.relayState != "" {
		urlQuery.Set("RelayState", sp.relayState)
	}
	idpURL.RawQuery = urlQuery.Encode()
	return idpURL.String(), nil
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

func getBindingLocation(desiredBinding string, supported []SingleSignOnService) (string, error) {
	for _, ssoSvc := range supported {
		if ssoSvc.Binding == desiredBinding {
			return ssoSvc.Location, nil
		}
	}
	return "", ErrBindingNotSupported
}
