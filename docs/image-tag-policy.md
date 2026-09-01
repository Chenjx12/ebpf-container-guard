# Image Tagging & Release Policy (v0.6.2)

> Aligned with [ADR-048](ADRs/048-ghcr-oci-image.md) / [ADR-049](ADRs/049-supply-chain-evidence-chain.md).
> This is the written form of the "image tag aligned with git tag" principle
> (decision #49): **a GHCR image tag is always the git tag string itself, with
> the `v` prefix.**

## 1. Mapping rule

| Git (tag) | GHCR (image tag) | Example |
|---|---|---|
| `v0.6.N` | `ghcr.io/chenjx12/ebpf-container-guard:v0.6.N` | `v0.6.2` → `...:v0.6.2` |

- Every push of a `v*` git tag triggers the `release.yml` workflow, which builds
  and pushes an image with **the identical tag string** (the `v` prefix is kept,
  not stripped).
- `latest` moves to the newest release after each run and is **not a version**:
  it only marks "most recent".
- Tag strings must be lowercase (Docker registry constraint). The GHCR repo is
  `ghcr.io/chenjx12/ebpf-container-guard` even though the GitHub owner is
  `Chenjx12` — the workflow computes this with `${GITHUB_REPOSITORY,,}`.

## 2. Which tag should you use?

| Scenario | Pull | Why |
|---|---|---|
| Demo / portfolio / thesis defense | **fixed version tag** (`v0.6.0`, `v0.6.1`, ...) | Deterministic behavior; `v0.6.0` is the permanent safety-net fallback |
| Trying the newest changes | `latest` | Moves on every release; never rely on it for a reproducible demo |
| K8s DaemonSet | `deploy/k8s/daemonset.yaml` image reference | Controlled separately within v0.6.x |

## 3. Git tag ≠ GitHub Release (decision #48 lesson)

A tag existing only means the tag exists. The **release** (with its assets) is
created by the workflow and must be verified by its `published_at` timestamp
after each release. Evidence lives on the **release assets**, not in the git tag.

## 4. Supply-chain evidence attached to every release (v0.6.2+)

| Asset | What it proves |
|---|---|
| `sbom.<tag>.cdx.json` | Software bill of materials (CycloneDX) — what is in the image |
| `trivy-report.<tag>.json` | Image-layer vulnerability scan (full JSON) |
| `trivy-fs-report.<tag>.json` | Dependency-layer scan (repo: requirements.txt / Dockerfile / sources) |

Both layers are independently gated (severity `CRITICAL,HIGH`, `ignore-unfixed`)
before the image is considered releasable; the reports are downloadable checkable
evidence, not just a badge.

## 5. Verification checklist after each release

1. GitHub Release exists with `published_at` set (decision #48).
2. All three assets above are attached and downloadable.
3. `docker pull ghcr.io/chenjx12/ebpf-container-guard:<tag>` succeeds with\n   registry credentials (the package requires registry auth — anonymous\n   `manifests/<tag>` GET returns 401, and an unprivileged token returns 403;\n   pull success is the real evidence the tag exists and is readable).
4. README "Container Image" quick start reproduces: pull → run (privileged flags) →
   dashboard reachable in 3 steps (real events visible).

---
*Maintained as part of the v0.6.x release discipline (bp_v06x).*