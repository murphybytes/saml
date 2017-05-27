package saml

import (
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
}

// NewRedirectBinding returns a url suitable for use to satisfy the SAML
// redirect binding.
// See http://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf Section 3.4
func NewRedirectBinding(spDescription *ServiceProvider, idpDecription *IDPSSODescriptor) (string, error) {
	_, err := getBindingLocation(redirectBinding, idpDecription.SingleSignOnService)
	if err != nil {
		return "", err
	}

	return "", nil
}

func getBindingLocation(desiredBinding string, supported []SingleSignOnService) (string, error) {
	for _, ssoSvc := range supported {
		if ssoSvc.Binding == desiredBinding {
			return ssoSvc.Location, nil
		}
	}
	return "", ErrBindingNotSupported
}
