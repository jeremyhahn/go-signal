package securevaluerecovery

// SVRCredentials contains authentication credentials for the secure value
// recovery service.
type SVRCredentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// AuthCheckRequest is the JSON body for checking SVR auth credentials.
type AuthCheckRequest struct {
	Passwords []string `json:"passwords"`
}

// AuthCheckResponse reports the match status for each submitted password.
type AuthCheckResponse struct {
	Matches map[string]string `json:"matches"`
}
