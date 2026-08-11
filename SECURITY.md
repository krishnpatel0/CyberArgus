# Security policy

## Reporting a vulnerability

Do not open a public issue for a security vulnerability. Use GitHub's private
security-advisory reporting feature for this repository. Include the affected
version, impact, sanitized reproduction steps, and a proposed remediation when
available. Do not include live credentials or third-party data.

## Supported versions

Security fixes are applied to the current `main` branch and the latest tagged
release. Older development snapshots are not supported.

## Deployment boundary

Argus processes sensitive intelligence and is not safe to expose directly to
the public Internet. Authentication must remain enabled, secrets must be unique,
and TLS should terminate at a reviewed reverse proxy, load balancer, or cluster
ingress. Configure collectors and recon only for assets and sources that the
operator is authorized to access.
