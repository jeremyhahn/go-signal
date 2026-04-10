package verification

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestApplySendOptions_Empty(t *testing.T) {
	t.Parallel()
	opts := ApplySendOptions()
	assert.Empty(t, opts.Carrier)
}

func TestApplySendOptions_WithCarrier(t *testing.T) {
	t.Parallel()
	opts := ApplySendOptions(WithCarrier("verizon"))
	assert.Equal(t, "verizon", opts.Carrier)
}

func TestApplySendOptions_WithCarrierOverride(t *testing.T) {
	t.Parallel()
	opts := ApplySendOptions(WithCarrier("att"), WithCarrier("tmobile"))
	assert.Equal(t, "tmobile", opts.Carrier)
}

func TestWithCarrier(t *testing.T) {
	t.Parallel()
	opt := WithCarrier("sprint")
	var o SendOptions
	opt(&o)
	assert.Equal(t, "sprint", o.Carrier)
}
