package main

import (
	"bytes"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"time"

	"github.com/murphybytes/saml"
	"github.com/murphybytes/saml/examples/svcprovider/generated"
	"github.com/pkg/errors"
)

type loginHandler struct {
	ssoProvider *saml.SSOProvider
}

func newLoginHandler(sp saml.ServiceProvider, metadata saml.IDPSSODescriptor) http.Handler {
	return &loginHandler{
		ssoProvider: saml.NewSSOProvider(&sp, &metadata),
	}
}

// ServeHTTP gets a URL that redirects to the IDP and logs in.
func (h *loginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	redirect, err := h.ssoProvider.RedirectBinding()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Location", redirect)
	w.WriteHeader(http.StatusFound)
}

type callbackHandler struct {
	ssoProvider *saml.SSOProvider
}

func newCallbackHandler(sp saml.ServiceProvider, metadata saml.IDPSSODescriptor) http.Handler {
	return &callbackHandler{
		ssoProvider: saml.NewSSOProvider(&sp, &metadata),
	}
}

// ServeHTTP handles the callback from the IDP that contains the authorization
// information.
func (h *callbackHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		writeServerError(w, err, "parsing form in callback handler")
		return
	}
	//
	// This is where the magic happens, we take the response from the IDP
	// to determine if authorization was successful
	//
	samlResponse := r.FormValue("SAMLResponse")
	id, err := h.ssoProvider.PostBindingResponse(samlResponse, time.Now())

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
	err = successPageTemplate.Execute(w, id.UserID)
	if err != nil {
		writeServerError(w, err, "writing success page")
	}
}

type homepageHandler struct{}

func newHomepageHandler() http.Handler {
	return &homepageHandler{}
}

func (h *homepageHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	page, errs := generated.Asset(homePagePath)
	if errs != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}
	contentTypeHeader(w)
	reader := bytes.NewReader(page)
	_, errs = io.Copy(w, reader)
	if errs != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}
}

func writeServerError(w http.ResponseWriter, err error, details string) {
	fmt.Println(errors.Wrap(err, details))
	w.WriteHeader(http.StatusInternalServerError)
}

func handleCallbackError(w http.ResponseWriter, errorText string) {
	errorPage, err := generated.Asset(errorPagePath)
	if err != nil {
		writeServerError(w, err, "reading error template")
		return
	}
	errorPageTemplate, err := template.New("").Parse(string(errorPage))
	if err != nil {
		writeServerError(w, err, "parsing error page template")
		return
	}
	err = errorPageTemplate.Execute(w, errorText)
	if err != nil {
		writeServerError(w, err, "writing error page template")
	}
}

func contentTypeHeader(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
}
