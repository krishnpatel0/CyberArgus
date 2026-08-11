# OSINT investigation module

Runs evidence-led investigations from a username, email, phone number, name, or
other supported identifier. Results are normalized into evidence tiers and can
be correlated or exported. Candidates are not presented as confirmed identity
matches without supporting evidence.

## Code map

| Path | Responsibility |
|---|---|
| `osint_api.py` | Unified HTTP routes, asynchronous job lifecycle, export |
| `osint_checker.py` | Site checks and subject search orchestration |
| `osint_engine/` | Investigation pipeline, correlation, adapters, scoring, and models |

## Interfaces and state

- Base route: `/api/osint`.
- Synchronous compatibility routes: `/search`, `/search/recursive`, `/csv-only`.
- Job routes: `/search/start`, `/search/status/{job_id}`,
  `/search/result/{job_id}`, `/search/cancel/{job_id}`.
- V2 routes: `/v2/investigate`, resumable job controls, `/v2/quick`,
  `/v2/calibrate`, and `/v2/export`.
- Job state is process-local in the current implementation. A backend restart
  ends in-flight OSINT jobs; this limitation must remain visible in changes and
  operational documentation.

## Development and validation

Add providers and checks inside `osint_engine` and preserve explicit timeouts,
confidence provenance, and evidence-tier semantics. The React workspace lives at
`modules-ui/src/modules/osint`. Use mock endpoints in unit tests; live provider
behavior is environment- and quota-dependent.
