BEGIN;

ALTER TABLE credential_profiles
  ADD COLUMN username text,
  ADD COLUMN active boolean NOT NULL DEFAULT true;

UPDATE credential_profiles
SET secret_ref = 'vault:' || id::text
WHERE secret_ref !~ '^vault:[0-9a-f-]{36}$';

CREATE OR REPLACE FUNCTION credential_profile_fill_secret_ref()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.secret_ref IS NULL OR btrim(NEW.secret_ref) = '' THEN
    NEW.secret_ref := 'vault:' || NEW.id::text;
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER credential_profiles_fill_secret_ref
  BEFORE INSERT ON credential_profiles
  FOR EACH ROW EXECUTE FUNCTION credential_profile_fill_secret_ref();

ALTER TABLE credential_profiles
  ADD CONSTRAINT credential_profile_username_nonempty
    CHECK (username IS NULL OR (length(btrim(username)) > 0 AND length(username) <= 320)),
  ADD CONSTRAINT credential_profile_secret_ref_opaque
    CHECK (secret_ref ~ '^vault:[0-9a-f-]{36}$');

CREATE INDEX idx_credential_profiles_active
  ON credential_profiles (organization_id, kind, name)
  WHERE active = true;

COMMIT;
