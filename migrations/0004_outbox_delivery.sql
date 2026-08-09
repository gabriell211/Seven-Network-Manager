BEGIN;

ALTER TABLE outbox_events
  ADD COLUMN attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  ADD COLUMN lease_owner text,
  ADD COLUMN lease_expires_at timestamptz,
  ADD COLUMN published_at timestamptz,
  ADD COLUMN last_error_code text,
  ADD COLUMN last_error_at timestamptz,
  ADD CONSTRAINT outbox_lease_pair CHECK (
    (lease_owner IS NULL AND lease_expires_at IS NULL)
    OR (lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL)
  );

CREATE INDEX idx_outbox_claim
  ON outbox_events (available_at, occurred_at, id)
  WHERE status IN ('pending', 'failed');

CREATE TABLE event_consumptions (
  consumer text NOT NULL,
  event_id uuid NOT NULL,
  consumed_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (consumer, event_id)
);

CREATE TABLE outbox_delivery_attempts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  event_id uuid NOT NULL REFERENCES outbox_events(id) ON DELETE CASCADE,
  attempt integer NOT NULL CHECK (attempt > 0),
  worker_id text NOT NULL,
  outcome text NOT NULL CHECK (outcome IN ('published', 'retry', 'dead_letter')),
  error_code text,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (event_id, attempt)
);

COMMIT;
