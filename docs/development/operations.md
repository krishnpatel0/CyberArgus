# Operations guide

| Intent | Command | Downloads/builds | Persistent data |
|---|---|---|---|
| First installation | `setup/setup.ps1` | prepares missing images and builds Argus | preserves existing `.env` |
| Daily start | `setup/start.ps1` | none | preserved |
| Daily stop | `setup/stop.ps1` | none | preserved |
| Load source changes | `setup/update.ps1` | no image build | preserved |
| Dependency/image change | `setup/rebuild.ps1` | cached build; pull only with `-Pull` | preserved |
| Destructive reset | `setup/fresh-start.ps1` | rebuild | deletes named volumes after exact confirmation |

BAT files are thin Command Prompt wrappers for the matching PowerShell scripts.
Use `update` for normal backend and frontend code changes. Use `rebuild` only when
the Dockerfile, Python requirements, or immutable image contents changed.

The backend health endpoint is `http://127.0.0.1:7777/health`. Inspect service
state with:

```powershell
docker compose --project-directory . -f docker/docker-compose.yml ps
docker compose --project-directory . -f docker/docker-compose.yml logs --tail 200 backend
```
