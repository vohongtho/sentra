# Ecosystem-specific SBOM generation (GitHub Actions snippets)

Each snippet produces `sbom.cdx.json` and then runs the same upload step as `sentra-container.yml`. Scanner coverage differs by ecosystem; verify output contains `purl`s with resolved versions before relying on it. Pin tool versions/digests.

| Ecosystem | Recommended generator | Snippet | Notes |
|---|---|---|---|
| PHP / Composer | CycloneDX PHP Composer plugin | `composer require --dev cyclonedx/cyclonedx-php-composer && composer CycloneDX:make-sbom --output-format=JSON --output-file=sbom.cdx.json` | Requires `composer.lock`; dev deps excluded with `--omit=dev`. |
| Node.js | `@cyclonedx/cyclonedx-npm` | `npx --yes @cyclonedx/cyclonedx-npm@1 --output-file sbom.cdx.json --omit dev` | Uses the lockfile; run after `npm ci`. |
| Java / Maven | CycloneDX Maven plugin | `mvn -B org.cyclonedx:cyclonedx-maven-plugin:2.9.1:makeAggregateBom -DoutputFormat=json && cp target/bom.json sbom.cdx.json` | Resolved versions from the reactor. Gradle: `org.cyclonedx.bom` plugin. |
| .NET / NuGet | CycloneDX .NET tool | `dotnet tool install --global CycloneDX && dotnet CycloneDX MySolution.sln -j -o . -fn sbom.cdx.json` | Run after `dotnet restore`. |
| Docker image | Syft | `anchore/sbom-action` (see `sentra-container.yml`) | Includes OS packages (rpm/deb/apk) with distro qualifiers; required for Amazon Linux backport matching. |
| Terraform | Trivy IaC (misconfiguration) | `trivy config --format sarif -o iac.sarif .` then import via **Project → Import** (SARIF) | Recorded as code findings; does not produce package inventory. |
| Python | `cyclonedx-py` | `pipx run cyclonedx-bom==4.* environment -o sbom.cdx.json --of JSON` | Run inside the built virtualenv/image for resolved versions. |
| Go | `cyclonedx-gomod` | `go run github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@v1 app -json -output sbom.cdx.json` | Binary-level SBOM preferred over `go.mod`. |
