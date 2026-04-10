package securestorage

// StorageCredentials contains authentication credentials for the secure
// storage service.
type StorageCredentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}
