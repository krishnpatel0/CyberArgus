# Argus Windows commands

Use the BAT files from Command Prompt or by double-clicking them. Use the matching
PS1 files from PowerShell. Each BAT file is only a wrapper around the PS1 file with
the same name.

| Command | When to use it | Downloads or builds? | Data impact |
|---|---|---|---|
| `setup.bat` | Once after cloning, or to finish an interrupted first installation | Yes: prepares missing infrastructure images and builds Argus | Preserves an existing `.env` unless `-Force` is explicitly supplied |
| `start.bat` | Every normal day | No: uses `--no-build --pull never` | Preserves everything |
| `stop.bat` | Every normal day | No | Stops containers but preserves containers, images, and volumes |
| `update.bat` | After normal backend or frontend source changes | No: compiles the UI locally, synchronizes source, and restarts only application services | Preserves containers, images, infrastructure, and volumes |
| `rebuild.bat` | Only after changing Python dependencies, the Dockerfile, or the immutable production image | Builds Argus using Docker cache | Preserves volumes |
| `rebuild.bat -Pull` | Only when intentionally updating Docker/base images | Yes: explicitly pulls current images and rebuilds | Preserves volumes |
| `test.bat` | Run the local quality checks | No dependency install; audits may contact package registries | No runtime-data changes |
| `test.bat -Install` | Once when preparing a local developer test environment | Yes: installs Python and Node development dependencies | No runtime-data changes |
| `fresh-start.bat` | Only when deliberately resetting all databases and runtime state | Rebuilds Argus | **Deletes all named-volume data after exact confirmation** |

Daily use:

```bat
setup\start.bat
setup\stop.bat
```

Load backend and frontend code changes without creating another Docker image:

```bat
setup\update.bat
```

`update.bat` requires the local development dependencies installed once with
`setup\test.bat -Install`. It never installs dependencies itself. It atomically
replaces the application source in the existing containers and restarts only the
API, workers, Breach, Intel, and Recon services. PostgreSQL, Redis, ClickHouse,
and Elasticsearch remain running.

First installation:

```bat
setup\setup.bat
setup\start.bat
```

Optional services use the same switch on setup, start, or rebuild. For example:

```bat
setup\setup.bat -AI
setup\start.bat -AI
```
