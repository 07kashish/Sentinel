# Local evidence for commit 89598e3 (2026-09-20)

One development machine, macOS arm64, Python 3.13. Not CI, not production, not independent.

- `run.json`: the full suite bound to the release inputs by `scripts/current_test_evidence.py`. 4,338 tests, 0 failures, 0 errors, 39 skipped; 611 PostgreSQL-parametrised cases, none skipped. Run with a local PostgreSQL 17 and with `SENTINEL_TEST_KUBECONFIG` pointing at a disposable kind cluster (Kubernetes 1.37), so `tests_arch/test_protected_change_journey.py` and `tests_arch/test_kubernetes_live_contract.py` executed rather than skipped. The JUnit file is retained outside the repository; its sha256 is in `run.json`.
- `image-gate.json`: `scripts/build_and_scan_image.py --scan-report` judging a Trivy scan (vuln, secret, misconfig; HIGH,CRITICAL) of the image built from this tree on the Wolfi base: PASS, no findings.

Not established here: a CI run (RISK R-019), deployed pods running the journey, an enforcing CNI, a customer identity provider, a root held outside the environment, a published or signed image, any customer.
