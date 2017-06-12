package main

import (
	"net/http"
	"time"

	"github.com/murphybytes/saml"
)

type logoutHandler struct {
	logoutProfile *saml.SingleLogOutProfile
}

func newLogoutHandler(sp saml.ServiceProvider, metadata *saml.EntityDescriptor) http.Handler {
	return &logoutHandler{
		logoutProfile: saml.NewSingleLogOutProfile(&sp, metadata),
	}
}

func (h *logoutHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		writeServerError(w, err, "parsing form logout redirect")
		return
	}
	email := r.FormValue(keyUID)
	redirectURL, err := h.logoutProfile.RedirectBinding(email)
	if err != nil {
		writeServerError(w, err, "building redirect binding")
	}
	// Trigger redirect in browser
	w.Header().Set("Location", redirectURL)
	w.WriteHeader(http.StatusFound)
}

type logoutCallbackHandler struct {
	logoutProfile *saml.SingleLogOutProfile
}

func newLogoutCallbackHandler(sp saml.ServiceProvider, metadata *saml.EntityDescriptor) http.Handler {
	return &logoutCallbackHandler{
		logoutProfile: saml.NewSingleLogOutProfile(&sp, metadata),
	}
}

func (h *logoutCallbackHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	cb, err := h.logoutProfile.HandlePostResponse(r, time.Now())
	if err != nil {
		writeServerError(w, err, "logout callback")
	}
	var location string
	if cb.SelfInitiatedLogout != nil {
		location = cb.SelfInitiatedLogout.RelayURL
	}
	if cb.ExternallyInitiatedLogout != nil {
		location = cb.ExternallyInitiatedLogout.RedirectURL
	}

	// redirect to hompage
	w.Header().Set("Location", location)
	w.WriteHeader(http.StatusFound)
}
