package recoverypassword

import "fmt"

// InvalidArgumentError indicates a required argument was missing or invalid.
type InvalidArgumentError struct {
	Field   string
	Message string
}

func (e *InvalidArgumentError) Error() string {
	return "invalid argument: " + e.Field + ": " + e.Message
}

// NotFoundError is returned by Store.Get when no entry exists for the given
// PNI. Mirrors how Java treats a missing DynamoDB row as Optional.empty()
// inside RegistrationRecoveryPasswords.lookup.
type NotFoundError struct {
	PNI string
}

func (e *NotFoundError) Error() string {
	return fmt.Sprintf("recoverypassword: no entry for pni %q", e.PNI)
}
