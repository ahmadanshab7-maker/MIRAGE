# Changelog

## 0.2.0 - 2026-11-03

### Added
- `python -m mirage` entry point.
- `--validate FILE` to check a snapshot's structure.
- `--diff A B` for a descriptive (non-scoring) comparison of two snapshots.
- `--compact` JSON output and `--strict` (exit code 2 when collectors report errors).
- GitHub Actions CI (Python 3.10-3.12).

### Fixed
- `/proc/cpuinfo` parsing: logical CPU count was wrong on multi-core machines
  and `vendor_id` was never captured.
- `--no-users` / `--no-filesystem` were ignored when `--collectors` was given.
- Duplicate names in `--collectors` ran a collector twice.
- Failed collectors now report a single consistent `errors` list.
- `users.account_statistics.shells` is sorted, so repeated runs are comparable.
- Hostname privacy test no longer false-fails when the hostname equals a
  legitimate value (e.g. `vm`); it now uses a unique sentinel hostname.
- README/pyproject: correct repo URL, removed `hostname` and CPU flags from the
  documented output (neither is collected).
