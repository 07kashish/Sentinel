# Evidence for commit 765c0e6 (2026-09-20, fourth pass)

One development machine plus one AWS host. Not CI, not production, not independent.

- `run.json`: the full suite bound to the release inputs. 4,427 tests, 0 failures, 0 errors, 39 skipped; 624 PostgreSQL-parametrised cases. Local PostgreSQL 17 and a disposable kind cluster (Kubernetes 1.37). The JUnit file is retained outside the repository; its sha256 is in `run.json`.
- `cloud-proof.json`: `scripts/run_cloud_proof.py`, PASSED, on commit 8f3de63 (the evidence-encryption and earlier work; the two later commits changed MCP analysis, the console and tests, not the journey's path). One EC2 m7i-flex.large in ap-south-1, Ubuntu 24.04 amd64, k3s v1.33.4 with containerd, flannel and kube-router's policy controller. Two Sentinel pods in production mode with a data key, pod-bound agent identity, admission and network policy both refusing bypass, a minted per-operation credential, attribution in managedFields, TLS under a private CA, offline evidence verification. The instance, security group and key pair were removed and the account was checked for leftovers.

Not established: a CI run (RISK R-019); the declared AWS topology (managed PostgreSQL and Redis, load balancer, object store, more than one node, IAM integration; RISK R-004); any request to the real AWS STS, CloudTrail or GitHub App APIs (RISK R-021); an independent failure domain; a published or signed image; an independent assessment; any customer.
