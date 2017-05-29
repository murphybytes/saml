package saml

import (
	"bytes"
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
	// RelayState url to redirect to after successfully logging in
	RelayState string
}

// SSOProvider supplies single sign on functionality
type SSOProvider struct {
	serviceProvder *ServiceProvider
	idpDescription *IDPSSODescriptor
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
	if sp.serviceProvder.RelayState != "" {
		urlQuery.Set("RelayState", sp.serviceProvder.RelayState)
	}
	idpURL.RawQuery = urlQuery.Encode()
	return idpURL.String(), nil
}

// Identity contains information about the principal that was authenticated
// with the IDP.  Typically check the user is known to the SP.
type Identity struct {
	UserID     string
	Audience   string
	Recipient  string
	RelayState string
}

// PostBindingResponse validates the IDP AuthnResponse. If successful information about the
// IDP authorized user is returned.
func (sp *SSOProvider) PostBindingResponse(samlResponse string) (*Identity, error) {
	_, err := decodeAuthResponse(samlResponse)
	if err != nil {
		return nil, errors.Wrap(err, "post binding response")
	}
	return nil, nil
}

func decodeAuthResponse(samlResponse string) (*Response, error) {
	decoded, err := base64.StdEncoding.DecodeString(samlResponse)
	if err != nil {
		return nil, errors.Wrap(err, "decoding auth response")
	}
	var response Response
	err = xml.NewDecoder(bytes.NewBuffer(decoded)).Decode(&response)
	if err != nil {
		return nil, err
	}
	return &response, nil
}

func getBindingLocation(desiredBinding string, supported []SingleSignOnService) (string, error) {
	for _, ssoSvc := range supported {
		if ssoSvc.Binding == desiredBinding {
			return ssoSvc.Location, nil
		}
	}
	return "", ErrBindingNotSupported
}
