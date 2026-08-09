BEGIN;

CREATE TABLE session_refresh_tokens (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  session_id uuid NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  family_id uuid NOT NULL,
  generation bigint NOT NULL DEFAULT 0 CHECK (generation >= 0),
  token_prefix text NOT NULL,
  token_hash bytea NOT NULL CHECK (octet_length(token_hash) = 32),
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  revoked_at timestamptz,
  replaced_by_id uuid REFERENCES session_refresh_tokens(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK (expires_at > created_at),
  UNIQUE (token_hash),
  UNIQUE (family_id, generation)
);

CREATE INDEX idx_session_refresh_tokens_session
  ON session_refresh_tokens (session_id, created_at DESC);

CREATE INDEX idx_session_refresh_tokens_active_family
  ON session_refresh_tokens (family_id, generation DESC)
  WHERE consumed_at IS NULL AND revoked_at IS NULL;

CREATE OR REPLACE FUNCTION validate_refresh_replacement() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  replacement_family uuid;
  replacement_generation bigint;
BEGIN
  IF NEW.replaced_by_id IS NULL THEN
    RETURN NEW;
  END IF;

  SELECT family_id, generation
    INTO replacement_family, replacement_generation
    FROM session_refresh_tokens
   WHERE id = NEW.replaced_by_id;

  IF replacement_family IS NULL
     OR replacement_family <> NEW.family_id
     OR replacement_generation <> NEW.generation + 1 THEN
    RAISE EXCEPTION 'invalid refresh-token replacement chain';
  END IF;

  RETURN NEW;
END;
$$;

CREATE CONSTRAINT TRIGGER session_refresh_tokens_validate_replacement
  AFTER INSERT OR UPDATE OF replaced_by_id ON session_refresh_tokens
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION validate_refresh_replacement();

COMMIT;
