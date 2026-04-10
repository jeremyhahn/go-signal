package rest

import "github.com/jeremyhahn/go-signal/pkg/devices"

// toLinkDeviceRequest converts the API entity to the domain LinkDeviceRequest.
func (e *LinkDeviceRequestEntity) toLinkDeviceRequest() *devices.LinkDeviceRequest {
	return &devices.LinkDeviceRequest{
		VerificationCode: e.VerificationCode,
		AccountAttributes: devices.DeviceAccountAttributes{
			FetchesMessages:   e.AccountAttributes.FetchesMessages,
			RegistrationId:    e.AccountAttributes.RegistrationId,
			PniRegistrationId: e.AccountAttributes.PniRegistrationId,
			Name:              e.AccountAttributes.Name,
			Capabilities:      e.AccountAttributes.Capabilities,
		},
		AciSignedPreKey: devices.SignedPreKeyEntity{
			KeyId:     e.AciSignedPreKey.KeyId,
			PublicKey: e.AciSignedPreKey.PublicKey,
			Signature: e.AciSignedPreKey.Signature,
		},
		PniSignedPreKey: devices.SignedPreKeyEntity{
			KeyId:     e.PniSignedPreKey.KeyId,
			PublicKey: e.PniSignedPreKey.PublicKey,
			Signature: e.PniSignedPreKey.Signature,
		},
		AciPqLastResortPreKey: devices.KEMSignedPreKeyEntity{
			KeyId:     e.AciPqLastResortPreKey.KeyId,
			PublicKey: e.AciPqLastResortPreKey.PublicKey,
			Signature: e.AciPqLastResortPreKey.Signature,
		},
		PniPqLastResortPreKey: devices.KEMSignedPreKeyEntity{
			KeyId:     e.PniPqLastResortPreKey.KeyId,
			PublicKey: e.PniPqLastResortPreKey.PublicKey,
			Signature: e.PniPqLastResortPreKey.Signature,
		},
	}
}
