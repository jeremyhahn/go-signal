//go:build smtp

package smtp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGatewayForCarrier_Known(t *testing.T) {
	t.Parallel()

	tests := []struct {
		carrier  string
		expected string
	}{
		{"verizon", "vtext.com"},
		{"att", "txt.att.net"},
		{"tmobile", "tmomail.net"},
		{"sprint", "messaging.sprintpcs.com"},
		{"uscellular", "email.uscc.net"},
		{"cricket", "sms.cricketwireless.net"},
	}

	for _, tt := range tests {
		t.Run(tt.carrier, func(t *testing.T) {
			t.Parallel()
			gw, ok := GatewayForCarrier(tt.carrier)
			assert.True(t, ok)
			assert.Equal(t, tt.expected, gw)
		})
	}
}

func TestGatewayForCarrier_Unknown(t *testing.T) {
	t.Parallel()

	gw, ok := GatewayForCarrier("nonexistent")
	assert.False(t, ok)
	assert.Empty(t, gw)
}

func TestFormatSMSAddress(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		number   string
		gateway  string
		expected string
	}{
		{
			name:     "without_plus",
			number:   "15551234567",
			gateway:  "vtext.com",
			expected: "15551234567@vtext.com",
		},
		{
			name:     "with_plus",
			number:   "+15551234567",
			gateway:  "txt.att.net",
			expected: "15551234567@txt.att.net",
		},
		{
			name:     "empty_number",
			number:   "",
			gateway:  "vtext.com",
			expected: "@vtext.com",
		},
		{
			name:     "plus_only",
			number:   "+",
			gateway:  "vtext.com",
			expected: "@vtext.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := FormatSMSAddress(tt.number, tt.gateway)
			assert.Equal(t, tt.expected, result)
		})
	}
}
