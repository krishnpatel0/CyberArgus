# OSINT workspace

`OSINTTools.jsx` owns investigation submission, job status, tiered evidence,
result summaries, and graph presentation. `api.js` is the module's only backend
adapter and targets `/api/osint`.

Maintain a visible distinction between candidates, observed evidence, and
correlated identity conclusions. Backend behavior is documented in
`backend/modules/osint/README.md`.
