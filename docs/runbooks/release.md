# Release Packaging Runbook

This runbook covers publishing immutable OhMyRasp control-plane release
artifacts to GitHub Container Registry.

## Release Artifacts

Each release publishes:

- API image: `ghcr.io/<namespace>/control-api:<version>`
- API SHA image: `ghcr.io/<namespace>/control-api:sha-<short-sha>`
- Web image: `ghcr.io/<namespace>/control-web:<version>`
- Web SHA image: `ghcr.io/<namespace>/control-web:sha-<short-sha>`
- Helm chart: `oci://ghcr.io/<namespace>/charts/ohmyrasp-control`
- BuildKit SBOM and max-mode provenance attestations attached to the pushed
  images.
- GitHub signed provenance attestations for the API image, web image, and Helm
  chart package.
- A mandatory Trivy vulnerability gate for the API and web release images.

The release workflow stamps `deploy/helm/ohmyrasp-control/Chart.yaml` and the
default `values.yaml` image references before packaging the chart. The chart
therefore defaults to the same API and web image version as the chart version.

## Version Rules

Use Docker-tag-safe semantic versions:

```text
0.1.0
0.1.0-rc.1
```

Do not use a leading `v` inside chart metadata or image tags. Do not use SemVer
build metadata such as `+build.1`, because Docker tags and Helm chart versions
would no longer match cleanly.

To stamp files locally:

```bash
deploy/scripts/set-release-version.sh 0.1.0 <ghcr-namespace> ghcr.io
```

If `<ghcr-namespace>` is omitted, the script uses `ohmyrasp`.

## Cut A Release

Run the normal validation workflow before tagging. From the repository root:

```bash
deploy/scripts/set-release-version.sh 0.1.0 <ghcr-namespace> ghcr.io
docker compose -f docker-compose.yml config --quiet
bash -n deploy/scripts/smoke-control-plane.sh deploy/scripts/set-release-version.sh
deploy/scripts/validate-helm-manifests.sh
deploy/scripts/validate-observability-assets.sh
```

Create and push a release tag:

```bash
git tag v0.1.0
git push origin v0.1.0
```

The `ohmyrasp-release` workflow derives `0.1.0` from the `v0.1.0` tag. A manual
release can also be started with the workflow dispatch input `version=0.1.0`.

## GitHub Action Pinning

Workflow Actions are pinned to immutable commit SHAs with the source tag noted
in a YAML comment. To update an Action, resolve the tag to a commit before
editing the workflow:

```bash
git ls-remote https://github.com/actions/checkout.git refs/tags/v6.0.0
git ls-remote https://github.com/actions/setup-go.git refs/tags/v5.5.0
git ls-remote https://github.com/actions/setup-node.git refs/tags/v6.0.0
git ls-remote https://github.com/actions/attest.git refs/tags/v4.1.0
```

Do not introduce floating Action references such as `@main`, `@master`, or a
major-only tag unless the release workflow is intentionally being relaxed for a
temporary investigation.

## Verify Published Artifacts

Inspect image manifests:

```bash
docker buildx imagetools inspect ghcr.io/<namespace>/control-api:0.1.0
docker buildx imagetools inspect ghcr.io/<namespace>/control-web:0.1.0
```

Pull the chart metadata:

```bash
helm show chart oci://ghcr.io/<namespace>/charts/ohmyrasp-control --version 0.1.0
helm show values oci://ghcr.io/<namespace>/charts/ohmyrasp-control --version 0.1.0
```

The chart values should point at:

```yaml
api:
  image:
    repository: ghcr.io/<namespace>/control-api
    tag: 0.1.0
web:
  image:
    repository: ghcr.io/<namespace>/control-web
    tag: 0.1.0
```

Verify signed provenance from the repository that produced the release:

```bash
gh attestation verify oci://ghcr.io/<namespace>/control-api:0.1.0 -R <owner>/<repo>
gh attestation verify oci://ghcr.io/<namespace>/control-web:0.1.0 -R <owner>/<repo>
helm pull oci://ghcr.io/<namespace>/charts/ohmyrasp-control --version 0.1.0
gh attestation verify ohmyrasp-control-0.1.0.tgz -R <owner>/<repo>
```

## Vulnerability Gate

The release workflow scans both pushed images before packaging the Helm chart.
The scanner runs from the digest-pinned Trivy image declared in
`deploy/docker-compose.tools.yml`. Dependabot keeps that Compose-managed reference
current, and the release script resolves it at runtime:

```text
deploy/scripts/resolve-tool-image.sh trivy
```

The gate fails the release on fixable `HIGH` or `CRITICAL` CVEs by default.
Run the same gate locally against published or local images:

```bash
deploy/scripts/scan-release-images.sh \
  ghcr.io/<namespace>/control-api:0.1.0 \
  ghcr.io/<namespace>/control-web:0.1.0
```

Supported gate tuning:

```bash
OHMYRASP_TRIVY_SEVERITIES=CRITICAL deploy/scripts/scan-release-images.sh <image>
OHMYRASP_TRIVY_IGNORE_UNFIXED=false deploy/scripts/scan-release-images.sh <image>
TRIVY_CACHE_DIR="$PWD/.trivy-cache" deploy/scripts/scan-release-images.sh <image>
```

Do not disable this step for releases. To update the scanner distribution,
resolve the new immutable digest first. `OHMYRASP_TRIVY_IMAGE` overrides must
also include an `@sha256:` digest:

```bash
docker buildx imagetools inspect aquasec/trivy:<version>
```

## Install A Published Chart

Log in if the package visibility requires authentication:

```bash
helm registry login ghcr.io
```

Install or upgrade:

```bash
helm upgrade --install ohmyrasp-control \
  oci://ghcr.io/<namespace>/charts/ohmyrasp-control \
  --version 0.1.0 \
  -n ohmyrasp --create-namespace \
  --wait
```

Use `--set api.image.tag=<version>` and `--set web.image.tag=<version>` only
when intentionally overriding chart defaults.

## Rollback Boundary

Treat the chart version, API image tag, web image tag, and database backup as a
single rollback boundary. If a release applied database migrations, follow
[upgrade-downgrade.md](./upgrade-downgrade.md) and restore the pre-release
PostgreSQL and ClickHouse backups before reinstalling the previous chart.
