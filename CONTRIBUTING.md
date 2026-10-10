# Contributing to Valkyrie

Thanks for helping make agents safe to be wrong.

## Licensing of contributions

- **Everything outside `controlplane/`** is MIT. Contributions are accepted under the
  [Developer Certificate of Origin](https://developercertificate.org/): sign every commit
  with `git commit -s`, which adds `Signed-off-by: Your Name <you@example.com>`.
- **`controlplane/`** is under the Valkyrie Enterprise License. Contributions there require
  a signed Contributor License Agreement granting the maintainer the right to license the
  contribution under the Enterprise License and any other license. Open an issue to request
  the CLA before submitting a pull request that touches `controlplane/`.

## Ground rules

- `make fmt` before committing (gofmt + `opa fmt`).
- Every policy rule ships with a test for its allow path and its deny reason, and a corpus
  case in `policy-corpus/` when it protects a customer-visible decision.
- Every change to `gateway/internal/pipeline` ships with a test proving the deny path still
  never leases a credential or executes.
- Manifests, policy data and role bindings are reviewed by the owning team in `CODEOWNERS`.
- Conventional Commits; `policy:` and `registry:` scopes trigger the bundle and registry jobs.
- `make test` and `make e2e` must be green.
