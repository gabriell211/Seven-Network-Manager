# Controlled Trial

The trial is a release mechanism for technical and commercial validation. It is not a shortcut around security.

## Goals

- Allow a company to test SNM in a real on-premise environment.
- Limit blast radius while the product is still being evaluated.
- Keep a path from pilot to commercial license without reinstalling.
- Collect only minimal and purposeful usage data when the customer consents.

## Trial Policy

The first policy is intentionally conservative:

| Limit | Default |
| --- | --- |
| Devices | 25 |
| Sites | 1 |
| Admin users | 2 |
| Write capabilities | Disabled by default |
| Duration | 30 days |

## Required Pilot Checklist

- Install backend, frontend, PostgreSQL, Redis and site runtime.
- Activate trial.
- Confirm runtime health.
- Run discovery in an allowed subnet.
- Build inventory with evidence/confidence.
- Read SNMP data from at least one printer or network device.
- Show dashboard status.
- Trigger one alert path.
- Export one report.
- Decide whether the account converts, extends or ends.

## Non-Negotiables

- Expired trial must not allow new controlled mutations.
- Trial state must be audited.
- Trial cannot expose unrestricted shell execution.
- Trial cannot require publishing the administrative API to the internet.
