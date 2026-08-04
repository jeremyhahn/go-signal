-- ============================================================================
-- REGISTRATION RECOVERY PASSWORDS
--
-- Mirrors Java Signal-Server's `RegistrationRecoveryPasswords` DynamoDB table.
-- A row stores a salted-token-hash keyed by phone number identifier (PNI).
-- Clients post the original password during re-registration; the server
-- verifies against the salted hash to skip the SMS verification flow.
--
-- expires_at is enforced application-side: Get() returns NotFound for any
-- row where now() >= expires_at. A future job may sweep expired rows on a
-- timer, but lazy expiry is sufficient for correctness.
-- ============================================================================

CREATE TABLE registration_recovery_passwords (
    pni         UUID         PRIMARY KEY,
    hash        TEXT         NOT NULL,
    salt        TEXT         NOT NULL,
    expires_at  TIMESTAMPTZ  NOT NULL,
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX registration_recovery_passwords_expires_idx
    ON registration_recovery_passwords (expires_at);
