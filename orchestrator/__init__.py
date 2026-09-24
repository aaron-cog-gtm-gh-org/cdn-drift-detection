"""Phase-03 Devin orchestration for CDN drift detection.

`run_detection` collects provider state over the simulator APIs, opens one
Devin detection session per domain (v3 API, service-user auth), validates the
structured output each session returns, and hands confirmed findings to
`remediate`, which routes them to remediation sessions (or defers them).
`collect` builds the per-domain provider bundles; `devin_client` is the thin
v3 client; `config` holds the environment knobs.
"""

__all__ = ["config", "devin_client", "collect", "run_detection", "remediate"]
