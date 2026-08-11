## Summary

Describe the change and why it is needed.

## Module scope

List every affected module or shared boundary. Start from [MODULES.md](../MODULES.md).

- Primary module:
- Cross-module consumers:
- Interface or data migration:

## Validation

- [ ] `./setup/test.ps1` or `setup/test.bat` passes
- [ ] Docker Compose configuration resolves
- [ ] New behavior has automated coverage
- [ ] Documentation reflects implemented behavior only
- [ ] The owning module README/manifest is current
- [ ] No credentials, customer data, breach data, or Telegram sessions are included

## Security and scope

Describe changes to authorization, rate limits, data handling, external requests,
or operational permissions. Write `None` when the change has no security impact.

## Visual evidence

For UI changes, attach sanitized before/after screenshots and state the viewport.
