package devices

// ProvisioningCodeExpiredError indicates the provisioning code has expired.
type ProvisioningCodeExpiredError struct {
	Code string
}

func (e *ProvisioningCodeExpiredError) Error() string {
	return "provisioning code expired: " + e.Code
}

// InvalidProvisioningCodeError indicates the provisioning code is not valid or
// does not correspond to an active provisioning session.
type InvalidProvisioningCodeError struct {
	Code string
}

func (e *InvalidProvisioningCodeError) Error() string {
	return "invalid provisioning code: " + e.Code
}
