# HTTP contract baseline

Public control-plane routes are versioned under `/api/v1`.

## Error envelope

```json
{
  "code": "runtime_unavailable",
  "message": "The site execution runtime is unavailable",
  "details": null,
  "requestId": "0198..."
}
```

Rules:
- `code` is stable and machine-consumable;
- `message` is safe for operators and contains no secret/internal stack;
- `details` is structured and optional;
- `requestId` correlates API, runtime and audit records;
- mutation endpoints will use `Idempotency-Key` where replay can occur;
- optimistic mutations will use ETag/version preconditions where lost update is possible;
- long-running network work returns a job resource rather than holding an HTTP request indefinitely.

OpenAPI generation is the next slice of #8; handwritten frontend DTOs are explicitly temporary until generated types replace them.
