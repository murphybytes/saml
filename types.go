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
	nameIDEmail = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
	// namespaces
	samlProtocalNamespace = "urn:oasis:names:tc:SAML:2.0:protocol"
	samlNamespace         = "urn:oasis:names:tc:SAML:2.0:assertion"
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

// SingleSignOnService contains information used to build redirect URL
type SingleSignOnService struct {
	XMLName  xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata SingleSignOnService"`
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
