package saml

import (
	"encoding/xml"
)

const (
	samlVersion    = "2.0"
	samlTimeFormat = "2006-01-02T15:04:05Z"
	// binding types
	redirectBinding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
	postBinding     = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
	soapBinding     = "urn:oasis:names:tc:SAML:2.0:bindings:SOAP"
	// user identifier support
	NameIDEmail             = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
	NameIDUnspecified       = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
	NameIDX509SubjectName   = "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName"
	NameIDWindowsDomainName = "urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName"
	NameIDKerboros          = "urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos"
	// namespaces
	samlProtocalNamespace = "urn:oasis:names:tc:SAML:2.0:protocol"
	samlNamespace         = "urn:oasis:names:tc:SAML:2.0:assertion"
	assertionTag          = "Assertion"
)

// EntityDescriptor specifies metadata for a single SAML entity.
type EntityDescriptor struct {
	XMLName          xml.Name         `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntityDescriptor"`
	EntityID         string           `xml:"entityID,attr"`
	IDPSSODescriptor IDPSSODescriptor `xml:"IDPSSODescriptor"`
}

// IDPSSODescriptor contains information about the identity provider.
type IDPSSODescriptor struct {
	XMLName             xml.Name              `xml:"urn:oasis:names:tc:SAML:2.0:metadata IDPSSODescriptor"`
	KeyDescriptors      []KeyDescriptor       `xml:"KeyDescriptor"`
	SingleLogoutService []SingleLogoutService `xml:"SingleLogoutService"`
	NameIDFormats       []NameIDFormat        `xml:"NameIDFormat"`
	SingleSignOnService []SingleSignOnService `xml:"SingleSignOnService"`
	Attributes          []Attribute           `xml:"Attribute"`
}

// KeyDescriptor element provides information about the cryptographic key(s) that an entity uses
// to sign data or receive encrypted keys, along with additional cryptographic details.
type KeyDescriptor struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata KeyDescriptor"`
	Use     string   `xml:"use,attr"`
	KeyInfo KeyInfo  `xml:"KeyInfo"`
}

// NameIDFormat information about user identifiers
type NameIDFormat struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata NameIDFormat"`
	Value   string   `xml:",chardata"`
}

// SingleSignOnService contains information about how to connect to the IDP and
// sign on.
type SingleSignOnService struct {
	XMLName  xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata SingleSignOnService"`
	Binding  string   `xml:"Binding,attr"`
	Location string   `xml:"Location,attr"`
}

// SingleLogoutService contains parameters needed to connect to the IPD and logout.
type SingleLogoutService struct {
	XMLName  xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata SingleLogoutService"`
	Binding  string   `xml:"Binding,attr"`
	Location string   `xml:"Location,attr"`
}

// KeyInfo wrapper for crypto key
type KeyInfo struct {
	XMLName  xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# KeyInfo"`
	X509Data X509Data `xml:"X509Data"`
}

// X509Data wraps the X509 cert.
type X509Data struct {
	XMLName         xml.Name        `xml:"http://www.w3.org/2000/09/xmldsig# X509Data"`
	X509Certificate X509Certificate `xml:"X509Certificate"`
}

// X509Certificate the certificate that will be used to verify the signature of AuthnResponse
type X509Certificate struct {
	XMLName xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# X509Certificate"`
	Data    string   `xml:",chardata"`
}

// AttributeValue contains the attributes supported by the identity provider
type AttributeValue struct {
	XMLName xml.Name
	Type    string `xml:"xsi:type,attr"`
	Value   string `xml:",innerxml"`
}

// Attribute contains a colleciton of AttributeValue
type Attribute struct {
	XMLName         xml.Name
	Name            string           `xml:",attr"`
	FriendlyName    string           `xml:",attr"`
	NameFormat      string           `xml:",attr"`
	AttributeValues []AttributeValue `xml:"AttributeValue"`
}

// AuthnRequest contains information needed to request authorization from
// an IDP
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf Section 3.4.1
type AuthnRequest struct {
	XMLName                     xml.Name
	SAMLP                       string                 `xml:"xmlns:samlp,attr"`
	SAML                        string                 `xml:"xmlns:saml,attr"`
	SAMLSIG                     string                 `xml:"xmlns:samlsig,attr,omitempty"`
	ID                          string                 `xml:"ID,attr"`
	Version                     string                 `xml:"Version,attr"`
	ProtocolBinding             string                 `xml:"ProtocolBinding,attr"`
	AssertionConsumerServiceURL string                 `xml:"AssertionConsumerServiceURL,attr"`
	Destination                 string                 `xml:"Destination,attr"`
	IssueInstant                string                 `xml:"IssueInstant,attr"`
	ProviderName                string                 `xml:"ProviderName,attr"`
	Issuer                      Issuer                 `xml:"Issuer"`
	NameIDPolicy                *NameIDPolicy          `xml:"NameIDPolicy,omitempty"`
	RequestedAuthnContext       *RequestedAuthnContext `xml:"RequestedAuthnContext,omitempty"`
	Signature                   *Signature             `xml:"Signature,omitempty"`
	originalString              string
}

// LogoutRequest is sent to the IDP when the Service Provider initiates the logout request.  If the IDP initiates
// the request, the logout request is sent to the service provider.
// See https://www.oasis-open.org/committees/download.php/35711/sstc-saml-core-errata-2.0-wd-06-diff.pdf Section 3.7.1
// Also Single Logout Profile
// See https://www.oasis-open.org/committees/download.php/35389/sstc-saml-profiles-errata-2.0-wd-06-diff.pdf Section 4.4.
type LogoutRequest struct {
	XMLName      xml.Name
	SAMLP        string `xml:"xmlns:samlp,attr"`
	SAML         string `xml:"xmlns:saml,attr"`
	SAMLSIG      string `xml:"xmlns:samlsig,attr,omitempty"`
	ID           string `xml:"ID,attr"`
	IssueInstant string `xml:"IssueInstant,attr"`
	Version      string `xml:"Version,attr"`
	Issuer       Issuer
	NameID       NameID
}

// LogoutResponse this is either send to the Service Provider in response to
// a LogoutRequest sent to the IDP, or may be returned to the IDP in the event
// the the IDP initiates the logout request.
type LogoutResponse struct {
	XMLName      xml.Name
	InResponseTo string `xml:"InResponseTo,attr"`
	Version      string `xml:"Version,attr"`
	IssueInstant string `xml:"IssueInstant,attr"`
	SAMLP        string `xml:"xmlns:samlp,attr"`
	SAMLSIG      string `xml:"xmlns:samlsig,attr,omitempty"`
	ID           string `xml:"ID,attr"`
	Issuer       Issuer `xml:"Issuer"`
	Status       Status `xml:"Status"`
}

// Issuer the issuer of the assertion
type Issuer struct {
	XMLName xml.Name
	Url     string `xml:",innerxml"`
}

// NameIDPolicy types of user identifiers requested by the assertion
// consumer
type NameIDPolicy struct {
	XMLName     xml.Name
	AllowCreate bool   `xml:"AllowCreate,attr"`
	Format      string `xml:"Format,attr"`
}

// RequestedAuthnContext requirements that the requestor places on the
// authorization context
type RequestedAuthnContext struct {
	XMLName              xml.Name
	SAMLP                string               `xml:"xmlns:samlp,attr"`
	Comparison           string               `xml:"Comparison,attr"`
	AuthnContextClassRef AuthnContextClassRef `xml:"AuthnContextClassRef"`
}

// Signature contains a digital signature of the enclosing element
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf Section 5
type Signature struct {
	XMLName        xml.Name
	Id             string `xml:"Id,attr"`
	SignedInfo     SignedInfo
	SignatureValue SignatureValue
	KeyInfo        KeyInfo
}

type AuthnContextClassRef struct {
	XMLName   xml.Name
	SAML      string `xml:"xmlns:saml,attr"`
	Transport string `xml:",innerxml"`
}

type SignedInfo struct {
	XMLName                xml.Name
	CanonicalizationMethod CanonicalizationMethod
	SignatureMethod        SignatureMethod
	SamlsigReference       SamlsigReference
}

type SignatureValue struct {
	XMLName xml.Name
	Value   string `xml:",innerxml"`
}

type CanonicalizationMethod struct {
	XMLName   xml.Name
	Algorithm string `xml:"Algorithm,attr"`
}

type SignatureMethod struct {
	XMLName   xml.Name
	Algorithm string `xml:"Algorithm,attr"`
}

type SamlsigReference struct {
	XMLName      xml.Name
	URI          string       `xml:"URI,attr"`
	Transforms   Transforms   `xml:",innerxml"`
	DigestMethod DigestMethod `xml:",innerxml"`
	DigestValue  DigestValue  `xml:",innerxml"`
}

type Transforms struct {
	XMLName   xml.Name
	Transform Transform
}

type DigestMethod struct {
	XMLName   xml.Name
	Algorithm string `xml:"Algorithm,attr"`
}

type DigestValue struct {
	XMLName xml.Name
}

type Transform struct {
	XMLName   xml.Name
	Algorithm string `xml:"Algorithm,attr"`
}

// Response is submitted to the service provider from the IDP via a callback.
// It will contain information about a authenticated user.
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf Section 3.3.3.
type Response struct {
	XMLName      xml.Name
	SAMLP        string `xml:"xmlns:samlp,attr"`
	SAML         string `xml:"xmlns:saml,attr"`
	SAMLSIG      string `xml:"xmlns:samlsig,attr"`
	Destination  string `xml:"Destination,attr"`
	ID           string `xml:"ID,attr"`
	Version      string `xml:"Version,attr"`
	IssueInstant string `xml:"IssueInstant,attr"`
	InResponseTo string `xml:"InResponseTo,attr"`

	Assertion Assertion `xml:"Assertion"`
	Signature Signature `xml:"Signature"`
	Issuer    Issuer    `xml:"Issuer"`
	Status    Status    `xml:"Status"`

	originalString string
}

type Assertion struct {
	XMLName            xml.Name
	ID                 string `xml:"ID,attr"`
	Version            string `xml:"Version,attr"`
	XS                 string `xml:"xmlns:xs,attr"`
	XSI                string `xml:"xmlns:xsi,attr"`
	SAML               string `xml:"saml,attr"`
	IssueInstant       string `xml:"IssueInstant,attr"`
	Issuer             Issuer `xml:"Issuer"`
	Subject            Subject
	Conditions         Conditions
	AttributeStatement AttributeStatement
}

type Subject struct {
	XMLName             xml.Name
	NameID              NameID
	SubjectConfirmation SubjectConfirmation
}

type Conditions struct {
	XMLName      xml.Name
	NotBefore    string `xml:",attr"`
	NotOnOrAfter string `xml:",attr"`
}

type NameID struct {
	XMLName xml.Name
	Format  string `xml:",attr"`
	Value   string `xml:",innerxml"`
}

type SubjectConfirmationData struct {
	InResponseTo string `xml:",attr"`
	NotOnOrAfter string `xml:",attr"`
	Recipient    string `xml:",attr"`
}

type SubjectConfirmation struct {
	XMLName                 xml.Name
	Method                  string `xml:",attr"`
	SubjectConfirmationData SubjectConfirmationData
}

type AttributeStatement struct {
	XMLName    xml.Name
	Attributes []Attribute `xml:"Attribute"`
}

type Status struct {
	XMLName    xml.Name
	StatusCode StatusCode `xml:"StatusCode"`
}

type StatusCode struct {
	XMLName xml.Name
	Value   string `xml:",attr"`
}
