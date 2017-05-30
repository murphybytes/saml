package saml

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"net/url"
	"time"

	"github.com/beevik/etree"
	"github.com/pkg/errors"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/russellhaering/goxmldsig/etreeutils"
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
// IDP authorized user is returned. The samlResponse argument is extracted from the form posted
// from the IDP in the SAMLResponse form value.
func (sp *SSOProvider) PostBindingResponse(samlResponse string, thisInstant time.Time) (*Identity, error) {
	decoded, err := base64.StdEncoding.DecodeString(samlResponse)
	if err != nil {
		return nil, errors.Wrap(err, "decoding saml response")
	}
	signed, err := sp.validateSignature(decoded)
	if err != nil {
		return nil, errors.Wrap(err, "validating auth response signature")
	}
	var xmlBuff bytes.Buffer
	doc := etree.NewDocument()
	doc.SetRoot(signed)
	_, err = doc.WriteTo(&xmlBuff)
	if err != nil {
		return nil, errors.Wrap(err, "processing post response xml")
	}
	var response Response
	err = xml.NewDecoder(&xmlBuff).Decode(&response)
	if err != nil {
		return nil, errors.Wrap(err, "decoding signed post response xml")
	}
	if !isStatusSuccess(response.Status.StatusCode.Value) {
		return nil, errors.Errorf("IDP Status: %s", response.Status.StatusCode.Value)
	}
	ok, err := timestampValid(&response, thisInstant)
	if err != nil {
		return nil, errors.Wrap(err, "validating auth response")
	}
	if !ok {
		return nil, errors.New("response timestamp is not valid")
	}
	id := &Identity{
		UserID:     response.Assertion.Subject.NameID.Value,
		RelayState: "/",
	}

	return id, nil
}

func (sp *SSOProvider) validateSignature(xmlBytes []byte) (*etree.Element, error) {
	doc := etree.NewDocument()
	err := doc.ReadFromBytes(xmlBytes)
	if err != nil {
		return nil, errors.Wrap(err, "xml for signature validation")
	}
	if doc.Root() == nil {
		return nil, errors.New("missing xml doc")
	}
	context, err := sp.getValidationContext()
	if err != nil {
		return nil, errors.Wrap(err, "setting up sig validation context")
	}
	root := doc.Root()
	validated, err := context.Validate(root)
	if err == nil {
		return validated, err
	}
	if err == dsig.ErrMissingSignature {
		err = etreeutils.NSFindIterate(root, samlNamespace, assertionTag, func(ctx etreeutils.NSContext, unverified *etree.Element) error {
			if unverified.Parent() != root {
				return errors.Errorf("assertion with unexpected parent: %s", unverified.Parent())
			}
			detached, err := etreeutils.NSDetatch(ctx, unverified)
			if err != nil {
				return err
			}
			signed, err := context.Validate(detached)
			if err != nil {
				return err
			}
			root.RemoveChild(unverified)
			root.AddChild(signed)
			return nil
		})
		if err != nil {
			return nil, err
		}
		return root, nil
	}
	return nil, err
}

func (sp *SSOProvider) getValidationContext() (*dsig.ValidationContext, error) {
	var certStore dsig.MemoryX509CertificateStore
	for _, key := range sp.idpDescription.KeyDescriptors {
		certData, err := base64.StdEncoding.DecodeString(key.KeyInfo.X509Data.X509Certificate.Data)
		if err != nil {
			return nil, errors.Wrap(err, "decoding x509 cert")
		}
		cert, err := x509.ParseCertificate(certData)
		if err != nil {
			return nil, errors.Wrap(err, "parsing x509 cert")
		}
		certStore.Roots = append(certStore.Roots, cert)
	}
	return dsig.NewDefaultValidationContext(&certStore), nil
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
