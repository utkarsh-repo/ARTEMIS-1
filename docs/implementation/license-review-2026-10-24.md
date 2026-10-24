# Technical dependency, provenance, and license review

**Date:** 2026-10-24  
**Release candidate:** ARTEMIS 2.2.30  
**Review type:** technical inventory only; not legal advice and not legal approval.  
**Evidence scope:** `requirements.txt`, repository `LICENSE`, package metadata and license files available in the current Python 3.13.5 validation environment, and the existing provenance register. No source-code similarity scan or qualified legal review was performed.

## Project and direct dependency

| Component | Version / declaration | License metadata observed | Provenance / notice evidence | Open consideration |
|---|---|---|---|---|
| ARTEMIS | project release 2.2.30; `LICENSE` says MIT, copyright 2026 | MIT text included in repository | `LICENSE` at repository root | Verify authorship, third-party contributions, and intended redistribution model before release |
| `requests` | `requests>=2.32.0,<3.0.0`; validation environment has 2.32.5 | Apache-2.0 | Metadata points to `https://github.com/psf/requests`; installed `requests-2.32.5.dist-info/licenses/LICENSE` | Runtime dependency is range-pinned, not lockfile-pinned; release SBOM should record exact resolved version |
| `urllib3` | transitive dependency; validation environment has 2.7.0 | MIT (SPDX `License-Expression` in installed metadata) | Metadata points to `https://github.com/urllib3/urllib3`; installed license file under `urllib3-*.dist-info/licenses/` | Confirm resolved version and include required license notice in a release bundle/SBOM process |
| `certifi` | transitive dependency; validation environment has 2026.5.20 | MPL-2.0 | Metadata points to `https://github.com/certifi/python-certifi`; installed license file under `certifi-*.dist-info/licenses/` | Review MPL notice/source obligations for the actual distribution form |
| `charset-normalizer` | transitive dependency; validation environment has 3.4.7 | MIT | Metadata points to `https://github.com/jawah/charset_normalizer`; installed license file under `charset_normalizer-*.dist-info/licenses/` | Preserve notice when redistributing the dependency |
| `idna` | transitive dependency; validation environment has 3.17 | BSD-3-Clause | Metadata points to `https://github.com/kjd/idna`; installed license file under `idna-*.dist-info/licenses/` | Preserve copyright/disclaimer notices as required by the license |

## Test-only tooling observed

The current test environment also contains `pytest 9.0.2` (MIT), `pluggy 1.6.0` (MIT), `iniconfig 2.3.0` (MIT), and `packaging 25.0` (metadata reports multiple bundled license texts). These are test-environment observations, not declared runtime dependencies in `requirements.txt`. If a release image or package bundles them, include them in the distribution's dependency inventory and notices.

The opt-in integration fixture uses `python:3.12-slim` as its base image. This is test infrastructure, not a production ARTEMIS worker image. Its Python, Debian base, and OS packages have their own licenses and notices; a fixture-image SBOM should be generated from the actual image digest before redistribution. The fixture is not claimed to be part of the ARTEMIS application release.

## Upstream references and provenance

The existing project register names these architectural/reference sources:

- Cairn: `https://github.com/oritera/Cairn`
- Cairn dispatcher design: `https://github.com/oritera/Cairn/blob/main/docs/specs/dispatcher-design.md`
- Cairn server protocol: `https://github.com/oritera/Cairn/blob/main/docs/specs/server-protocol.md`
- ARTEX: `https://github.com/trhhubsd/ARTEX`

The existing provenance register records a maintainer assertion that no upstream source code was copied and that the projects were consulted for architectural concepts and reference material. That assertion has not been independently verified by a line-by-line source comparison. It is not enough, by itself, to determine whether any attribution, trademark, patent, notice, or other obligations apply.

No Cairn/ARTEX source files or license text were newly imported in this batch. Before any distribution, record the exact upstream revisions and retrieval dates actually relied upon; preserve any notices for material included; compare source and generated artifacts; and have a qualified reviewer examine the applicable upstream license and project-specific terms.

## Distribution obligations and release gate

1. Generate a release-specific SBOM from the exact packaged artifact and resolved dependency set; this environment inventory is not a substitute for that SBOM.
2. Preserve the ARTEMIS MIT notice and all applicable third-party copyright/license notices when redistributing dependencies.
3. Review Apache-2.0, MPL-2.0, BSD-3-Clause, MIT, and any licenses surfaced by the exact release SBOM against the chosen packaging/distribution model.
4. Confirm whether upstream source, expressive text, schemas, fixtures, generated outputs, or assets were copied/adapted, and determine any resulting obligations.
5. Record a qualified human/legal reviewer, date, reviewed references, decision, exceptions, and evidence.

**Decision:** `ART-LICENSE-001` remains `IN_PROGRESS`. Technical inventory work is recorded, but no legal compatibility determination is made and no automated status transition is allowed.
