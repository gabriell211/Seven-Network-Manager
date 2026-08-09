BEGIN;

ALTER TABLE credential_profiles
  ADD COLUMN username text,
  ADD COLUMN active boolean NOT NULL DEFAULT true;

ALTER TABLE credential_profiles
  ADD CONSTRAINT credential_profile_username_nonempty
    CHECK (username IS NULL OR (length(btrim(username)) > 0 AND length(username) <= 320)),
  ADD CONSTRAINT credential_profile_secret_ref_opaque
    CHECK (secret_ref ~ '^vault:[0-9a-f-]{36}$');

CREATE INDEX idx_credential_profiles_active
  ON credential_profiles (organization_id, kind, name)
  WHERE active = true;

COMMIT;
