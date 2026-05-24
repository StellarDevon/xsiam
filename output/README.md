# output/

Runtime directory — **git-ignored** except for `config.yaml` and `*.bat` launchers.

```
output/
├── config.yaml      ← runtime config (committed as template; edit locally)
├── restart.bat      ← stop everything, start infra + xsiam (one-shot)
├── start.bat        ← auto-restart loop (stays open in terminal)
├── bin/             ← compiled binaries  (git-ignored)
│   ├── xsiam.exe
│   └── seed.exe
├── logs/            ← stdout/stderr from all processes  (git-ignored)
├── data/
│   ├── etcd/        ← etcd data directory  (git-ignored)
│   └── redis/       ← Redis persistence dump  (git-ignored)
└── screenshots/     ← UI screenshots  (git-ignored)
```

## Quick start

```bat
:: First time or after code changes:
rebuild.bat

:: Every subsequent run:
output\restart.bat      (or double-click)

:: Keep terminal open with auto-restart on crash:
output\start.bat
```

## Ports

| Port  | Purpose |
|-------|---------|
| 18080 | Web console — React SPA + all business APIs |
| 18090 | Internal only — auth / RBAC / audit svc + agent webhook |
| 8529  | ArangoDB (Docker) |
| 6379  | Redis |

## Config resolution order

`xsiam.exe` looks for `config.yaml` in:
1. Current working directory (run from `output/`)
2. Same directory as the exe (`output/bin/`)
3. One level up from the exe (`output/`)

The launchers run from `output/`, so `output/config.yaml` is always found.
