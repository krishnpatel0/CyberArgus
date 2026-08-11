# Backend modules

This directory contains the domain modules mounted by the Argus application.
Each module owns its domain logic, API adapter, tests, and module manifest. Core
platform capabilities remain in `backend/arguswatch`; shared infrastructure must
not be copied into a module.

| Module | Purpose | Primary entry point | Frontend |
|---|---|---|---|
| [Breach intelligence](breach/README.md) | Authorized corpus search and relationship traversal | `breach_api.py` / `search_engine/main.py` | `modules-ui/src/modules/breach` |
| [OSINT](osint/README.md) | Evidence-led subject investigation | `osint_api.py` | `modules-ui/src/modules/osint` |
| [Image intelligence](image_intel/README.md) | Image metadata, OCR, vision, reverse-search, and geolocation evidence | `routes.py` | `modules-ui/src/modules/image-intelligence` |
| [Telegram intelligence](telegram_intel/README.md) | Authorized channel analysis, alerts, graph summaries, and STIX | `routes.py` | Main Argus dashboard |

## Module contract

- Keep public routes behind the unified Argus authentication boundary.
- Put reusable platform code in `arguswatch`, not in multiple modules.
- Keep network operations bounded by timeouts, retries, and scope checks.
- Add focused tests under `backend/tests`; name the owning module in the file.
- Update the module README and `module.yaml` when interfaces or dependencies change.
- Never add a standalone Dockerfile, dependency file, `.env`, or launcher inside a
  module. All roles use the repository-level image, dependency lock, Compose
  topology, and setup commands.

See [the module contract](../../docs/development/module-contract.md) for the full
change checklist.
