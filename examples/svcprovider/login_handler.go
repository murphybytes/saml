package main

import (
	"html/template"
	"net/http"
	"time"

	"github.com/murphybytes/saml"
	"github.com/murphybytes/saml/examples/svcprovider/generated"
)

type loginHandler struct {
	loginProfile *saml.SingleSignOnProfile
}

func newLoginHandler(sp saml.ServiceProvider, metadata saml.IDPSSODescriptor) http.Handler {
	return &loginHandler{
		loginProfile: saml.NewSingleSignOnProfile(&sp, &metadata),
	}
}

// ServeHTTP gets a URL that redirects to the IDP and logs in.
func (h *loginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		writeServerError(w, err, "parsing login form")
	}
	rs := r.FormValue(keyRelayState)
	redirect, err := h.loginProfile.RedirectBinding(saml.RelayState(rs))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	// Trigger redirect in the browser
	w.Header().Set("Location", redirect)
	w.WriteHeader(http.StatusFound)
}

type loginCallbackHandler struct {
	loginProfile *saml.SingleSignOnProfile
}

func newLoginCallbackHandler(sp saml.ServiceProvider, metadata saml.IDPSSODescriptor) http.Handler {
	return &loginCallbackHandler{
		loginProfile: saml.NewSingleSignOnProfile(&sp, &metadata),
	}
}

// ServeHTTP handles the callback from the IDP that contains the authorization
// information.
func (h *loginCallbackHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		writeServerError(w, err, "parsing form in callback handler")
		return
	}
	//
	// This is where the magic happens, we take the response from the IDP
	// to determine if authorization was successful
	//
	samlResponse := r.FormValue(saml.ResponseQueryKey)
	cbResponse, err := h.loginProfile.HandlePostResponse(samlResponse, time.Now())

	contentTypeHeader(w)
	// normally we'd display log in failed, but for the purposes of this
	// example we'll show the error
	if err != nil {
		handleCallbackError(w, err.Error())
		return
	}

	successPage, err := generated.Asset(successPagePath)
	if err != nil {
		writeServerError(w, err, "reading success page")
		return
	}

	successPageTemplate, err := template.New("").Parse(string(successPage))
	if err != nil {
		writeServerError(w, err, "parsing error template")
		return
	}
	args := struct {
		User       string
		RelayState string
	}{
		User:       cbResponse.Identity.UserID,
		RelayState: r.FormValue(saml.RelayStateQueryKey),
	}
	err = successPageTemplate.Execute(w, args)
	if err != nil {
		writeServerError(w, err, "writing success page")
	}
}
