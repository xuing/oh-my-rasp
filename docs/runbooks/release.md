# Release Packaging Runbook

This runbook covers cutting and verifying immutable OhMyRASP releases across GitHub Releases, GitHub Container Registry (GHCR), and OCI Helm registries. Release automation lives in [.github/workflows/ohmyrasp-release.yml](../../.github/workflows/ohmyrasp-release.yml) and [deploy/scripts/publish-github-release.sh](../../deploy/scripts/publish-github-release.sh).

## Release Artifacts

Each release (`v<version>`, e.g. `v0.2.0-alpha.1` or `v0.2.0`) publishes:

**GitHub Release assets (15 files)**:
- Standard Java agents: `ohmyrasp-agent-java8.jar`, `ohmyrasp-agent-java11.jar`, `ohmyrasp-agent-java17.jar`, `ohmyrasp-agent-jdk21.jar`, `ohmyrasp-agent.jar`
- Standalone daemonless shirudo Java upatch JARs: `ohmyrasp-java8.jar`, `ohmyrasp-java11.jar`, `ohmyrasp-java17.jar`, `ohmyrasp-jdk21.jar`, `ohmyrasp-jdk25.jar`
- JDK 21 Shirudo package ready to sign: `ohmyrasp-jdk21-shirudo.tar.gz`
- shirudo Beefile bundle: `ohmyrasp-shirudo-upatches-<version>.tar.gz` (the 5 package directories, `Beefile`s, `README.md`s, `build.sh`, and staged JARs)
- Rust host daemon: `ohmyrasp-daemon-linux-amd64.tar.gz`
- Helm chart archive: `ohmyrasp-control-<version>.tgz`
- Checksums: `SHA256SUMS.txt`

**GHCR container and OCI artifacts**:
- API image: `ghcr.io/<namespace>/control-api:<version>` and `ghcr.io/<namespace>/control-api:sha-<short-sha>`
- Web image: `ghcr.io/<namespace>/control-web:<version>` and `ghcr.io/<namespace>/control-web:sha-<short-sha>`
- Helm chart: `oci://ghcr.io/<namespace>/charts/ohmyrasp-control` (`--version <version>`)
- BuildKit SBOM and max-mode provenance attestations on both container images
- GitHub signed provenance attestations for the API image, web image, Helm chart archive, Java agent JARs, shirudo upatch JARs and bundle, and daemon tarball
- Trivy CVE scan gate on `control-api` and `control-web` before packaging the Helm chart

`deploy/scripts/publish-github-release.sh` is idempotent: rerunning updates release notes and `--clobber`s assets, asserts `EXPECTED_ASSETS` (`12`) are present, marks hyphenated versions (`-*`) as pre-releases without `Latest`, and reconciles `Latest` using SemVer ordering (`sort -V`) so backfilling an older tag never steals `Latest`.

The GitHub Release publisher (`deploy/scripts/publish-github-release.sh`) is idempotent: a rerun updates notes, `--clobber`s assets, verifies all 15 assets are uploaded, marks pre-releases (`-*`) as prerelease without `Latest`, and reconciles `Latest` by SemVer so backfilling an older tag never steals `Latest` from a newer release.

The workflow stamps `deploy/helm/ohmyrasp-control/Chart.yaml` and `values.yaml` via `deploy/scripts/set-release-version.sh` before packaging so chart defaults match `<version>`.

## Version Rules

Use Docker-tag-safe semantic versions without a leading `v` or `+build` metadata:

```text
0.2.0
0.2.0-alpha.1
```

To stamp chart metadata and default image tags locally:

```bash
deploy/scripts/set-release-version.sh 0.2.0-alpha.1 <ghcr-namespace> ghcr.io
```

If `<ghcr-namespace>` is omitted, `set-release-version.sh` defaults to `ohmyrasp`.

## Cut a Release

Run the pre-tag validation checklist from the repository root:

```bash
deploy/scripts/set-release-version.sh 0.2.0-alpha.1 <ghcr-namespace> ghcr.io
docker compose -f docker-compose.yml config --quiet
bash -n deploy/scripts/smoke-control-plane.sh deploy/scripts/set-release-version.sh deploy/scripts/publish-github-release.sh
python3 deploy/shirudo/gen-readmes.py --check
./deploy/shirudo/verify-shirudo-upatch.sh --beefile-only
python3 java-agent/scripts/gen-detection-coverage.py --check
deploy/scripts/validate-helm-manifests.sh
deploy/scripts/validate-observability-assets.sh
```

If you have already staged the four `ohmyrasp-<track>.jar` files under `deploy/shirudo/ohmyrasp-<track>/`, omit `--beefile-only` on `./deploy/shirudo/verify-shirudo-upatch.sh` (pass `--version <version>` if checking non-default Beefile versions) to validate the JAR manifests and `META-INF/ohmyrasp-shirudo.properties` as well.

Update [CHANGELOG.md](../../CHANGELOG.md) if cutting a changelogged release, then create and push the tag:

```bash
git tag v0.2.0-alpha.1
git push origin v0.2.0-alpha.1
```

`ohmyrasp-release.yml` strips the leading `v` from `v*.*.*` tags, or accepts manual `workflow_dispatch` with `version=<version>` (e.g. `0.2.0-alpha.1`).

## GitHub Action Pinning

Workflow Actions are pinned to immutable commit SHAs with the source tag in a comment. Resolve tags before updating `.github/workflows/ohmyrasp-release.yml`:

```bash
git ls-remote https://github.com/actions/checkout.git refs/tags/v7.0.1
git ls-remote https://github.com/actions/setup-go.git refs/tags/v7.0.0
git ls-remote https://github.com/actions/setup-node.git refs/tags/v7.1.0
git ls-remote https://github.com/actions/attest.git refs/tags/v4.2.2
```

Do not use floating `@main`, `@master`, or major-only tags.

## Verify Published Artifacts

Download and verify GitHub Release assets, checksums, and provenance attestations:

```bash
gh release download v0.2.0-alpha.1 -R <owner>/<repo> -D dist-verify
(cd dist-verify && sha256sum -c SHA256SUMS.txt)

for jar in dist-verify/*.jar; do
  gh attestation verify "$jar" -R <owner>/<repo>
done
gh attestation verify dist-verify/ohmyrasp-shirudo-upatches-0.2.0-alpha.1.tar.gz -R <owner>/<repo>
gh attestation verify dist-verify/ohmyrasp-daemon-linux-amd64.tar.gz -R <owner>/<repo>
gh attestation verify dist-verify/ohmyrasp-control-0.2.0-alpha.1.tgz -R <owner>/<repo>
```

Inspect GHCR container manifests and OCI Helm chart metadata, and verify their provenance:

```bash
docker buildx imagetools inspect ghcr.io/<namespace>/control-api:0.2.0-alpha.1
docker buildx imagetools inspect ghcr.io/<namespace>/control-web:0.2.0-alpha.1

gh attestation verify oci://ghcr.io/<namespace>/control-api:0.2.0-alpha.1 -R <owner>/<repo>
gh attestation verify oci://ghcr.io/<namespace>/control-web:0.2.0-alpha.1 -R <owner>/<repo>

helm show chart oci://ghcr.io/<namespace>/charts/ohmyrasp-control --version 0.2.0-alpha.1
helm show values oci://ghcr.io/<namespace>/charts/ohmyrasp-control --version 0.2.0-alpha.1
helm pull oci://ghcr.io/<namespace>/charts/ohmyrasp-control --version 0.2.0-alpha.1
gh attestation verify ohmyrasp-control-0.2.0-alpha.1.tgz -R <owner>/<repo>
```

The chart values must point to `ghcr.io/<namespace>/control-api:<version>` and `ghcr.io/<namespace>/control-web:<version>`.

## Vulnerability Gate

`ohmyrasp-release.yml` scans both pushed images with the digest-pinned Trivy image from `deploy/docker-compose.tools.yml` (resolved via `deploy/scripts/resolve-tool-image.sh trivy`) before packaging the Helm chart. By default the gate fails on fixable `HIGH` or `CRITICAL` CVEs:

```bash
deploy/scripts/scan-release-images.sh \
  ghcr.io/<namespace>/control-api:0.2.0-alpha.1 \
  ghcr.io/<namespace>/control-web:0.2.0-alpha.1
```

Supported overrides:

```bash
OHMYRASP_TRIVY_SEVERITIES=CRITICAL deploy/scripts/scan-release-images.sh <image>
OHMYRASP_TRIVY_IGNORE_UNFIXED=false deploy/scripts/scan-release-images.sh <image>
TRIVY_CACHE_DIR="$PWD/.trivy-cache" deploy/scripts/scan-release-images.sh <image>
```

`OHMYRASP_TRIVY_IMAGE` overrides must include an `@sha256:` digest (`docker buildx imagetools inspect aquasec/trivy:<version>`).

## Install a Published Chart

```bash
helm registry login ghcr.io

helm upgrade --install ohmyrasp-control \
  oci://ghcr.io/<namespace>/charts/ohmyrasp-control \
  --version 0.2.0-alpha.1 \
  -n ohmyrasp --create-namespace \
  --wait
```

Use `--set api.image.tag=<version>` and `--set web.image.tag=<version>` only when overriding chart defaults.

## Rollback Boundary

Treat the chart version, API image tag, web image tag, and database backup as one rollback boundary. If a release applied migrations, follow [upgrade-downgrade.md](./upgrade-downgrade.md) to restore pre-release PostgreSQL and ClickHouse backups before reinstalling the previous chart.
