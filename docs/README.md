# Argus Unified documentation

This documentation separates fast-moving developer guides from implementation
reports. It describes verified, implemented behavior and names current
limitations rather than presenting roadmap work as complete.

## Developer documentation

- [System architecture](development/architecture.md)
- [Module ownership map](../MODULES.md)
- [Module contract](development/module-contract.md)
- [Testing guide](development/testing.md)
- [Operations guide](development/operations.md)
- [Frontend workspace guide](../modules-ui/README.md)
- [Container topology](../docker/README.md)

## Repository diagrams

- [System architecture](diagrams/argus-architecture-simple.svg)
- [Module ownership map](diagrams/module-map.svg)
- [Request lifecycle](diagrams/request-lifecycle.svg)
- [Contributor workflow](diagrams/developer-workflow.svg)

## Module reports

The Word reports contain module logic, implemented mathematical methods,
flowcharts, and researched comparisons current to their generation date.

- [Core Platform](modules/01_Argus_Core_Platform.docx)
- [OSINT Investigation](modules/02_OSINT_Investigation_Module.docx)
- [Breach Search and Graph](modules/03_Breach_Search_and_Graph_Module.docx)
- [Telegram Threat Intelligence](modules/04_Telegram_Threat_Intelligence_Module.docx)
- [PII, IOC and STIX](modules/05_PII_IOC_and_STIX_Module.docx)
- [Complete System Walkthrough](Argus_Unified_Complete_Walkthrough.docx)

Image Intelligence was integrated after those implementation reports. Its
current developer contract is documented in
[`backend/modules/image_intel/README.md`](../backend/modules/image_intel/README.md);
the historical DOCX reports have not been silently rewritten to claim coverage.

## Black-and-white implementation flowcharts

- [Core platform flow](flowcharts/core-platform-flow.svg)
- [OSINT investigation flow](flowcharts/osint-investigation-flow.svg)
- [Breach correlation flow](flowcharts/breach-correlation-flow.svg)
- [Telegram intelligence flow](flowcharts/telegram-intelligence-flow.svg)
- [PII / IOC / STIX flow](flowcharts/pii-ioc-stix-flow.svg)
- [Unified platform flow](flowcharts/unified-platform-flow.svg)

## Verification boundary

The repository quality gate covers isolated Python tests, selected application
smoke tests, frontend lint/build, dependency audits, and Compose resolution. Live
provider and full multi-database behavior additionally require configured local
services, credentials where applicable, and authorized data/sources.
