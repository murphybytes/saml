package saml

const (
	// These are response status codes described in the core SAML spec section
	// 3.2.2.1 See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
	Success int = iota
	Requestor
	Responder
	VersionMismatch
	AuthnFailed
	InvalidAttrNameOrValue
	InvalidNameIDPolicy
	NoAuthnContext
	NoAvailableIDP
	NoPassive
	NoSupportedIDP
	PartialLogout
	ProxyCountExceeded
	RequestDenied
	RequestUnsupported
	RequestVersionDeprecated
	RequestVersionTooHigh
	RequestVersionTooLow
	ResourceNotRecognized
	TooManyResponses
	UnknownAttrProfile
	UnknownPrincipal
	UnsupportedBinding
)

var statusMap = map[string]int{
	"urn:oasis:names:tc:SAML:2.0:status:Success":                  Success,
	"urn:oasis:names:tc:SAML:2.0:status:Requester":                Requestor,
	"urn:oasis:names:tc:SAML:2.0:status:Responder":                Responder,
	"urn:oasis:names:tc:SAML:2.0:status:VersionMismatch":          VersionMismatch,
	"urn:oasis:names:tc:SAML:2.0:status:AuthnFailed":              AuthnFailed,
	"urn:oasis:names:tc:SAML:2.0:status:InvalidAttrNameOrValue":   InvalidAttrNameOrValue,
	"urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy":      InvalidNameIDPolicy,
	"urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext":           NoAuthnContext,
	"urn:oasis:names:tc:SAML:2.0:status:NoAvailableIDP":           NoAvailableIDP,
	"urn:oasis:names:tc:SAML:2.0:status:NoPassive":                NoPassive,
	"urn:oasis:names:tc:SAML:2.0:status:NoSupportedIDP":           NoSupportedIDP,
	"urn:oasis:names:tc:SAML:2.0:status:PartialLogout":            PartialLogout,
	"urn:oasis:names:tc:SAML:2.0:status:ProxyCountExceeded":       ProxyCountExceeded,
	"urn:oasis:names:tc:SAML:2.0:status:RequestDenied":            RequestDenied,
	"urn:oasis:names:tc:SAML:2.0:status:RequestUnsupported":       RequestUnsupported,
	"urn:oasis:names:tc:SAML:2.0:status:RequestVersionDeprecated": RequestVersionDeprecated,
	"urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooLow":     RequestVersionTooLow,
	"urn:oasis:names:tc:SAML:2.0:status:ResourceNotRecognized":    ResourceNotRecognized,
	"urn:oasis:names:tc:SAML:2.0:status:TooManyResponses":         TooManyResponses,
	"urn:oasis:names:tc:SAML:2.0:status:UnknownAttrProfile":       UnknownAttrProfile,
	"urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal":         UnknownPrincipal,
	"urn:oasis:names:tc:SAML:2.0:status:UnsupportedBinding":       UnsupportedBinding,
}

func isStatusSuccess(status string) bool {
	return statusMap[status] == Success
}
