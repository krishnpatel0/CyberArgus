# Module contract

Every module has one backend directory, zero or one frontend directory, a
`module.yaml`, and a README that states implemented behavior and limitations.

## Backend rules

- Route adapters validate input and apply the unified authentication/role policy.
- Domain services do not import UI code or read browser state.
- SQL is parameterized. Subprocesses use argument vectors rather than shell text.
- External calls set explicit connect/read timeouts, response bounds, and retries.
- Jobs expose honest terminal states; a missing provider is not a successful result.
- State locations and retention behavior are documented.

## Frontend rules

- Place module pages, styles, and API adapters in `modules-ui/src/modules/<id>`.
- Use `shared/api/http.js` for the authenticated session and error normalization.
- Do not create hidden fallback/mock data in production code.
- Visualizations must remain readable at supported viewport sizes and expose a
  non-graph representation for data that matters to an investigation.

## Pull request checklist

1. Update the owning README and `module.yaml` if an interface changed.
2. Add or update focused tests and run the repository quality gate.
3. Verify authorization, scope, logging, retention, and secret handling.
4. List cross-module consumers and migration impact.
5. Confirm no live intelligence, credentials, sessions, or generated reports are
   present in the patch.
