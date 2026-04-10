package directory

// DirectoryCredentials contains authentication credentials for the contact
// discovery service.
type DirectoryCredentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}
