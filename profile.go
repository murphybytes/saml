package saml

// Identity contains information about the principal that was authenticated
// with the IDP.  Typically check the user is known to the SP.
type Identity struct {
	UserID     string
	Audience   string
	Recipient  string
	RelayState string
}

type SelfInitiatedLogout struct {
	RelayURL string
}

type ExternallyInitiatedLogout struct {
	RedirectURL string
}

type CallbackResponse struct {
	*Identity
	*SelfInitiatedLogout
	*ExternallyInitiatedLogout
}
