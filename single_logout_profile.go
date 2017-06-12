package saml

import (
	"bytes"
	"encoding/xml"
	"net/http"
	"net/url"
	"time"

	"github.com/beevik/etree"

	"github.com/pkg/errors"
)

// SingleLogOutProfile provides single log out services
type SingleLogOutProfile struct {
	serviceProvider *ServiceProvider
	entity          *EntityDescriptor
}

// NewSingleLogOutProfile creates a SingleLogOutProfile
func NewSingleLogOutProfile(spDescription *ServiceProvider, entity *EntityDescriptor) *SingleLogOutProfile {
	return &SingleLogOutProfile{
		serviceProvider: spDescription,
		entity:          entity,
	}
}

// RedirectBinding generates a redirect binding that can be used to
// send a logout request for the user identified by email to an IDP.
func (slp *SingleLogOutProfile) RedirectBinding(email string) (string, error) {
	idpRedirectURL, err := getSingleLogoutBindingLocation(redirectBinding, slp.entity.IDPSSODescriptor.SingleLogoutService)
	if err != nil {
		return "", err
	}
	requestID, err := getUniqueID()
	if err != nil {
		return "", errors.Wrap(err, "getting id for redirect binding")
	}
	request := LogoutRequest{
		XMLName: xml.Name{
			Local: "samlp:LogoutRequest",
		},
		ID:           requestID,
		SAMLP:        samlProtocalNamespace,
		SAML:         samlNamespace,
		IssueInstant: time.Now().UTC().Format(samlTimeFormat),
		Version:      samlVersion,
		Issuer: Issuer{
			XMLName: xml.Name{
				Local: "saml:Issuer",
			},
			Url: slp.serviceProvider.IssuerURI,
		},
		NameID: NameID{
			Format: NameIDEmail,
			Value:  email,
		},
	}
	var encodedRequest bytes.Buffer
	err = xml.NewEncoder(&encodedRequest).Encode(request)
	if err != nil {
		return "", errors.Wrap(err, "encoding logout request")
	}

	logoutQueryVal, err := deflate(&encodedRequest)
	if err != nil {
		return "", errors.Wrap(err, "compressing logout request")
	}
	idpURL, err := url.Parse(idpRedirectURL)
	if err != nil {
		return "", errors.Wrap(err, "Unable to parse IDP URL")
	}
	query := idpURL.Query()
	query.Set(RequestQueryKey, logoutQueryVal)
	idpURL.RawQuery = query.Encode()
	return idpURL.String(), nil
}

// HandlePostResponse validates the IDP response to the logout request.  If successful, nil is returned
// and the host should be logged out.
func (slp *SingleLogOutProfile) HandlePostResponse(r *http.Request, thisInstant time.Time) (*CallbackResponse, error) {
	err := r.ParseForm()
	if err != nil {
		return nil, errors.Wrap(err, "parsing logout handler")
	}
	compressedSaml := r.FormValue(ResponseQueryKey)
	if compressedSaml == "" {
		compressedSaml = r.FormValue(RequestQueryKey)
	}
	if compressedSaml == "" {
		return nil, errors.New("invalid response")
	}
	inflated, err := inflate(compressedSaml)
	if err != nil {
		return nil, errors.Wrap(err, "handling logout response")
	}
	resp, err := createLogout(inflated)
	if err != nil {
		return nil, errors.Wrap(err, "parsing logout response in callback")
	}
	switch t := resp.(type) {
	case *LogoutRequest:
		return slp.handleLogoutRequest(t)
	case *LogoutResponse:
		return slp.handleLogoutResponse(t)
	}
	return nil, errors.New("logout application error")
}

func (slp *SingleLogOutProfile) handleLogoutRequest(r *LogoutRequest) (*CallbackResponse, error) {
	if slp.entity.EntityID != r.Issuer.Url {
		return nil, errors.Errorf("issuer is not correct %q", r.Issuer.Url)
	}
	requestID, err := getUniqueID()
	if err != nil {
		return nil, errors.Wrap(err, "handling logout response")
	}
	response := &LogoutResponse{
		Issuer: Issuer{
			XMLName: xml.Name{
				Local: "saml:Issuer",
			},
			Url: slp.serviceProvider.IssuerURI,
		},
		InResponseTo: r.ID,
		IssueInstant: time.Now().UTC().Format(samlTimeFormat),
		Version:      samlVersion,
		SAMLP:        samlProtocalNamespace,
		ID:           requestID,
		Status: Status{
			StatusCode: StatusCode{
				Value: "urn:oasis:names:tc:SAML:2.0:status:Success",
			},
		},
	}
	var encoded bytes.Buffer
	err = xml.NewEncoder(&encoded).Encode(response)
	if err != nil {
		return nil, errors.Wrap(err, "encoding logout response")
	}
	queryVal, err := deflate(&encoded)
	if err != nil {
		return nil, errors.Wrap(err, "deflate logout response")
	}
	idpURLRoot, err := getSingleLogoutBindingLocation(redirectBinding, slp.entity.IDPSSODescriptor.SingleLogoutService)
	if err != nil {
		return nil, err
	}
	idpURL, err := url.Parse(idpURLRoot)
	if err != nil {
		return nil, errors.Wrap(err, "parsing idp url")
	}
	idpQuery := idpURL.Query()
	idpQuery.Set(RequestQueryKey, queryVal)
	idpURL.RawQuery = idpQuery.Encode()
	cb := &CallbackResponse{
		ExternallyInitiatedLogout: &ExternallyInitiatedLogout{
			RedirectURL: idpURL.String(),
		},
	}
	return cb, nil
}

func (slp *SingleLogOutProfile) handleLogoutResponse(r *LogoutResponse) (*CallbackResponse, error) {
	if slp.entity.EntityID != r.Issuer.Url {
		return nil, errors.Errorf("issuer is not correct %q", r.Issuer.Url)
	}
	// TODO: add more vaidation
	if !isStatusSuccess(r.Status.StatusCode.Value) {
		return nil, errors.Errorf("logout failed: %q", r.Status.StatusCode.Value)
	}
	cb := &CallbackResponse{
		SelfInitiatedLogout: &SelfInitiatedLogout{
			RelayURL: "/",
		},
	}
	return cb, nil
}

func getSingleLogoutBindingLocation(desiredBinding string, services []SingleLogoutService) (string, error) {
	for _, svc := range services {
		if svc.Binding == desiredBinding {
			return svc.Location, nil
		}
	}
	return "", ErrBindingNotSupported
}

// checks issuer, if issuer and if we have a login request or response to
// determine who initiated the logout request
func createLogout(samlResponse string) (interface{}, error) {
	doc := etree.NewDocument()
	err := doc.ReadFromString(samlResponse)
	if err != nil {
		return false, errors.Wrap(err, "parsing logout saml")
	}
	tag := doc.Root().Tag
	switch tag {
	case "LogoutRequest":
		var lr LogoutRequest
		err := xml.NewDecoder(bytes.NewBufferString(samlResponse)).Decode(&lr)
		if err != nil {
			return nil, errors.Wrap(err, "decoding logout request")
		}
		return &lr, nil
	case "LogoutResponse":
		var lr LogoutResponse
		err := xml.NewDecoder(bytes.NewBufferString(samlResponse)).Decode(&lr)
		if err != nil {
			return nil, errors.Wrap(err, "decoding logout response")
		}
		return &lr, nil
	}
	return nil, errors.Errorf("unexpected request type %q", tag)
}
