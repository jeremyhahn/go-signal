package accounts

import (
	"testing"
)

// --- IdentityType.String ---

func TestIdentityType_String_ACI(t *testing.T) {
	if got := IdentityTypeACI.String(); got != "ACI" {
		t.Errorf("IdentityTypeACI.String() = %q, want %q", got, "ACI")
	}
}

func TestIdentityType_String_PNI(t *testing.T) {
	if got := IdentityTypePNI.String(); got != "PNI" {
		t.Errorf("IdentityTypePNI.String() = %q, want %q", got, "PNI")
	}
}

func TestIdentityType_String_Unknown(t *testing.T) {
	unknown := IdentityType(99)
	if got := unknown.String(); got != "Unknown" {
		t.Errorf("unknown IdentityType.String() = %q, want %q", got, "Unknown")
	}
}

// --- Account.IdentityUUID ---

func TestAccount_IdentityUUID_ACI(t *testing.T) {
	a := &Account{UUID: "aci-uuid", PNI: "pni-uuid"}
	got := a.IdentityUUID(IdentityTypeACI)
	if got != "aci-uuid" {
		t.Errorf("IdentityUUID(ACI) = %q, want %q", got, "aci-uuid")
	}
}

func TestAccount_IdentityUUID_PNI(t *testing.T) {
	a := &Account{UUID: "aci-uuid", PNI: "pni-uuid"}
	got := a.IdentityUUID(IdentityTypePNI)
	if got != "pni-uuid" {
		t.Errorf("IdentityUUID(PNI) = %q, want %q", got, "pni-uuid")
	}
}

func TestAccount_IdentityUUID_Unknown(t *testing.T) {
	a := &Account{UUID: "aci-uuid", PNI: "pni-uuid"}
	got := a.IdentityUUID(IdentityType(99))
	if got != "" {
		t.Errorf("IdentityUUID(unknown) = %q, want empty", got)
	}
}

func TestAccount_IdentityUUID_NilAccount(t *testing.T) {
	var a *Account
	if got := a.IdentityUUID(IdentityTypeACI); got != "" {
		t.Errorf("nil.IdentityUUID(ACI) = %q, want empty", got)
	}
	if got := a.IdentityUUID(IdentityTypePNI); got != "" {
		t.Errorf("nil.IdentityUUID(PNI) = %q, want empty", got)
	}
}

// --- ServiceIdentifierString ---

func TestServiceIdentifierString_ACI(t *testing.T) {
	got := ServiceIdentifierString(IdentityTypeACI, "abc-uuid")
	if got != "abc-uuid" {
		t.Errorf("ServiceIdentifierString(ACI) = %q, want %q", got, "abc-uuid")
	}
}

func TestServiceIdentifierString_PNI(t *testing.T) {
	got := ServiceIdentifierString(IdentityTypePNI, "pni-uuid")
	if got != "PNI:pni-uuid" {
		t.Errorf("ServiceIdentifierString(PNI) = %q, want %q", got, "PNI:pni-uuid")
	}
}

func TestServiceIdentifierString_EmptyUUID(t *testing.T) {
	tests := []struct {
		identityType IdentityType
		name         string
	}{
		{IdentityTypeACI, "ACI"},
		{IdentityTypePNI, "PNI"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ServiceIdentifierString(tt.identityType, "")
			if got != "" {
				t.Errorf("ServiceIdentifierString(%s, empty) = %q, want empty", tt.name, got)
			}
		})
	}
}

func TestServiceIdentifierString_UnknownType(t *testing.T) {
	// An unknown IdentityType (neither ACI nor PNI) should not add the "PNI:" prefix.
	got := ServiceIdentifierString(IdentityType(99), "some-uuid")
	if got != "some-uuid" {
		t.Errorf("ServiceIdentifierString(unknown, uuid) = %q, want %q", got, "some-uuid")
	}
}
