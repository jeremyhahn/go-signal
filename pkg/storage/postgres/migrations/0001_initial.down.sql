-- 0001_initial.down.sql
-- Reverses 0001_initial.up.sql. Wrapped in a transaction by the runner.

DROP TABLE IF EXISTS spam_reports;
DROP TABLE IF EXISTS storage_items;
DROP TABLE IF EXISTS storage_manifests;
DROP TABLE IF EXISTS fido2_sessions;
DROP TABLE IF EXISTS fido2_credentials;
DROP TABLE IF EXISTS verification_sessions;
DROP TABLE IF EXISTS profiles;
DROP TABLE IF EXISTS messages;
DROP TABLE IF EXISTS groups;
DROP TABLE IF EXISTS username_links;
DROP TABLE IF EXISTS usernames_reserved;
DROP TABLE IF EXISTS usernames_confirmed;
DROP TABLE IF EXISTS provisioning_sessions;
DROP TABLE IF EXISTS prekeys_kem_lastresort;
DROP TABLE IF EXISTS prekeys_ec_signed;
DROP TABLE IF EXISTS prekeys_kem_onetime;
DROP TABLE IF EXISTS prekeys_ec_onetime;
DROP TABLE IF EXISTS accounts;
