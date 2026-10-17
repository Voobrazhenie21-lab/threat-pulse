# Contributing to ThreatPulse

Thanks for your interest in contributing! ThreatPulse is a **zero-runtime-
dependency** tool — everything runs on the Python standard library. This is a
core design property: keep it that way.

## Ground Rules

- **Zero runtime dependencies.** No third-party packages in
  `[project.dependencies]`.
- **Offline-first.** All core detections (heuristics, entropy, signatures) must
  work without network access. Online lookups (e.g., AbuseIPDB) are optional
  enhancements and must degrade gracefully when unavailable.
- **Defang by default in output.** Reports shown to users must defang IOCs.

## Development Setup

```bash
git clone https://github.com/Voobrazhenie21-lab/threat-pulse.git
cd threat-pulse

uv sync
uv run pytest tests/ -v

# or: pip install -e ".[dev]" && pytest tests/ -v
```

## Adding a New Detection / Enrichment

1. Add the logic in the appropriate module under `threat_pulse/`.
2. Add tests in `tests/` and sample data in `samples/`.
3. Update the README (architecture, usage examples) if behavior is
   user-visible.
4. Bump the version in `pyproject.toml` and `threat_pulse/__init__.py`.

## Pull Request Checklist

- [ ] `pytest tests/ -v` passes locally.
- [ ] New detections have tests and sample indicators.
- [ ] README updated for user-facing changes.
- [ ] No secrets, API keys, or live IOCs tied to real incidents in commits.
- [ ] Commit messages follow conventional style (`feat:`, `fix:`, `docs:`, `ci:`).

## Release Process

1. Ensure CI is green on `main`.
2. Bump the version in `pyproject.toml`.
3. Tag the release: `git tag -a vX.Y.Z -m "vX.Y.Z" && git push origin vX.Y.Z`.
4. Create a GitHub Release from the tag with a changelog.
5. Publish to PyPI (`threatpulse-cli`) via the release workflow.
