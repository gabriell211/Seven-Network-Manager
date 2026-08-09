BEGIN;

ALTER TABLE credential_ciphertexts
  RENAME COLUMN nonce TO data_nonce;

ALTER TABLE credential_ciphertexts
  ADD COLUMN envelope_version smallint NOT NULL DEFAULT 1
    CHECK (envelope_version = 1),
  ADD COLUMN wrapped_dek_nonce bytea,
  ADD COLUMN wrapped_dek bytea;

ALTER TABLE credential_ciphertexts
  ADD CONSTRAINT credential_ciphertexts_data_nonce_size
    CHECK (octet_length(data_nonce) = 12),
  ADD CONSTRAINT credential_ciphertexts_aad_hash_size
    CHECK (octet_length(aad_hash) = 32),
  ADD CONSTRAINT credential_ciphertexts_wrapped_dek_nonce_size
    CHECK (wrapped_dek_nonce IS NULL OR octet_length(wrapped_dek_nonce) = 12),
  ADD CONSTRAINT credential_ciphertexts_wrapped_dek_size
    CHECK (wrapped_dek IS NULL OR octet_length(wrapped_dek) > 32);

-- No released build has written credential_ciphertexts yet. Keep the migration
-- explicit rather than silently changing migration 0002; a deployment that did
-- write pre-envelope rows must fail closed and migrate/re-encrypt them through a
-- controlled operator procedure before enabling credential use.
DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM credential_ciphertexts
    WHERE wrapped_dek_nonce IS NULL OR wrapped_dek IS NULL
  ) THEN
    RAISE EXCEPTION 'legacy credential ciphertext rows require controlled re-encryption';
  END IF;
END;
$$;

ALTER TABLE credential_ciphertexts
  ALTER COLUMN wrapped_dek_nonce SET NOT NULL,
  ALTER COLUMN wrapped_dek SET NOT NULL;

COMMIT;
