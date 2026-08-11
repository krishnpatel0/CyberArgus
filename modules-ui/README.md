# Argus modules workspace

This React/Vite application hosts module-specific investigation workspaces at
`/modules`. The main Argus dashboard remains server-rendered from
`backend/arguswatch/static`; this workspace is embedded into the same product
shell and uses the same authentication session.

## Source boundaries

```text
src/
|-- modules/
|   |-- breach/             Breach search and connection graph
|   |-- osint/              OSINT investigation and evidence views
|   `-- image-intelligence/ Image investigation jobs and results
`-- shared/
    |-- api/                Authenticated HTTP and URL configuration
    |-- context/            Cross-module UI state
    `-- visualization/      Reusable graph rendering
```

Keep domain-specific components, styles, API adapters, and tests in the owning
module. Move code to `shared` only after at least two modules need the same
behavior and the abstraction has a stable interface.

## Commands

```powershell
Set-Location modules-ui
npm ci
npm run lint
npm run build
```

For development against the unified backend, configure the Vite proxy in
`vite.config.js` and run `npm run dev`. For the Docker stack, use
`setup/update.ps1` to compile and load frontend and backend source changes
without rebuilding the application image.
