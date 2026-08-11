# Breach workspace

`BreachData.jsx` owns the analyst workflow for authorized corpus searches and
connection graphs. `api.js` calls the unified `/api/breach` adapter;
`graphApi.js` normalizes graph requests and responses. Shared graph rendering is
in `src/shared/visualization`.

Keep raw records out of browser logs, error telemetry, snapshots, and fixtures.
Backend behavior is documented in
`backend/modules/breach/README.md`.
