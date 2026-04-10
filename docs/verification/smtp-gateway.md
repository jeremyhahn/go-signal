# SMTP SMS Gateway

The SMTP transport delivers verification codes by sending emails through carrier SMS gateways. Most US carriers operate email-to-SMS gateways that accept messages at addresses like `15551234567@vtext.com` and deliver them as text messages to the phone.

**Package**: `pkg/verification/smtp/`

**Build tag**: `smtp`

```bash
go build -tags smtp ./...
```

## How It Works

```
go-signal -> SMTP server -> carrier email gateway -> phone (SMS)
```

The transport connects to an SMTP server using `smtp.PlainAuth`, composes a minimal email with the verification code in the body, and sends it to an address derived from the phone number and carrier gateway domain.

## Supported Carriers

| Carrier | Key | Gateway Domain |
|---|---|---|
| Verizon | `verizon` | `vtext.com` |
| AT&T | `att` | `txt.att.net` |
| T-Mobile | `tmobile` | `tmomail.net` |
| Sprint | `sprint` | `messaging.sprintpcs.com` |
| US Cellular | `uscellular` | `email.uscc.net` |
| Cricket | `cricket` | `sms.cricketwireless.net` |

The carrier map is defined in `pkg/verification/smtp/carriers.go` as `CarrierGateways`. Use `GatewayForCarrier(carrier)` to look up a domain programmatically.

## Address Formatting

E.164 phone numbers are converted to email addresses by stripping the leading `+` and appending `@{gateway}`:

```
+15551234567 -> 15551234567@vtext.com
```

The `FormatSMSAddress(number, gatewayDomain)` function handles this conversion.

## Configuration

```go
type TransportConfig struct {
    Host            string            // SMTP server hostname
    Port            int               // SMTP server port
    Username        string            // SMTP authentication username
    Password        string            // SMTP authentication password
    FromAddress     string            // sender email address
    UseTLS          bool              // whether to use STARTTLS
    CarrierGateways map[string]string // override default carrier gateways
    DefaultCarrier  string            // fallback carrier when none specified
}
```

Example YAML configuration:

```yaml
verification:
  transport: smtp
  smtp:
    host: smtp.example.com
    port: 587
    username: signal@example.com
    password: kms://secrets/smtp-password
    fromAddress: verify@example.com
    useTls: true
    defaultCarrier: verizon
```

## Carrier Resolution

When `SendCode` is called, the transport resolves the carrier in this order:

1. **WithCarrier option**: If `WithCarrier("att")` is passed as a `SendOption`, that carrier is used.
2. **DefaultCarrier**: Falls back to `TransportConfig.DefaultCarrier`.
3. **Error**: If both are empty, returns `*CarrierNotFoundError`.

Once the carrier key is resolved, the transport looks up the gateway domain:

1. Check `TransportConfig.CarrierGateways` (custom overrides) first.
2. Fall back to the built-in `CarrierGateways` map.
3. Return `*CarrierNotFoundError` if neither contains the key.

This two-level lookup lets you add custom carriers or override gateway domains for existing ones without modifying the built-in map.

## Email Format

The transport constructs a minimal RFC 2822 message:

```
From: verify@example.com
To: 15551234567@vtext.com
Subject: Signal Verification

Your Signal verification code is: 483291
```

The message is sent using `smtp.SendMail` with `smtp.PlainAuth` credentials.

## Error Handling

If `smtp.SendMail` fails, the error is wrapped in a `*verification.TransportError`:

```go
&verification.TransportError{
    Transport:   "smtp",
    Destination: "+15551234567",
    Cause:       err,  // underlying SMTP error
}
```

The `TransportError` implements `Unwrap()` so callers can inspect the root cause with `errors.As`.

## Limitations

- **US carriers only.** The built-in gateway map covers major US carriers. International carriers require custom `CarrierGateways` entries, and many international carriers do not support email-to-SMS at all.
- **Delivery not guaranteed.** Gateway availability varies. Some carriers throttle or block messages from unknown senders.
- **Rate limiting.** Carriers may silently drop messages if too many are sent in a short window. The transport does not implement client-side rate limiting.
- **PlainAuth over TLS.** The transport uses `smtp.PlainAuth`, which sends credentials in cleartext. The `UseTLS` flag should be enabled in production to ensure the SMTP connection is encrypted via STARTTLS before authentication occurs.
- **No delivery confirmation.** SMTP gateways do not provide delivery receipts. A successful `SendMail` call means the SMTP server accepted the message, not that the phone received it.
