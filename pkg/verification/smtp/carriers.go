//go:build smtp

// Package smtp provides an SMTP-based verification transport that delivers
// verification codes via email-to-SMS carrier gateways.
package smtp

// CarrierGateways maps carrier names to SMS email gateway domains.
var CarrierGateways = map[string]string{
	"verizon":    "vtext.com",
	"att":        "txt.att.net",
	"tmobile":    "tmomail.net",
	"sprint":     "messaging.sprintpcs.com",
	"uscellular": "email.uscc.net",
	"cricket":    "sms.cricketwireless.net",
}

// GatewayForCarrier returns the email gateway domain for the given carrier.
// Returns empty string and false if the carrier is not found.
func GatewayForCarrier(carrier string) (string, bool) {
	gw, ok := CarrierGateways[carrier]
	return gw, ok
}

// FormatSMSAddress formats an E.164 phone number as an SMS email address.
// The phone number should not include the leading '+'.
func FormatSMSAddress(number string, gatewayDomain string) string {
	if len(number) > 0 && number[0] == '+' {
		number = number[1:]
	}
	return number + "@" + gatewayDomain
}
