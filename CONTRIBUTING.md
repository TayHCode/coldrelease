# Contributing

Keep the runtime dependency list empty and tests synthetic. Run
`python3 -m unittest discover -s tests -q` before submitting changes.
Add regression fixtures for privacy/reporting, history coverage or export behavior.
Never include actual credentials or personal term lists in issues or fixtures.
To release, bump `version` in `pyproject.toml` and `VERSION` in `release_check.py`
together (`tests/test_version.py` checks they match), then tag the merge commit `v<version>`.
In the public repo the tag push runs `.github/workflows/release.yml`, which builds and tests the
wheel but uploads nothing. To publish, run `gh workflow run release.yml --ref v<version> -f publish=true`
and approve the `pypi` environment deployment. PyPI must list the repo, `release.yml` and the `pypi`
environment as a trusted publisher, and the environment must require the owner's review.
