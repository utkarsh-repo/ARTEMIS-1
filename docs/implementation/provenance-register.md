# ARTEMIS implementation provenance and distribution review

**Scope:** ARTEMIS 2.2.18 source and release packaging. This register records known inspiration and unresolved distribution decisions; it is not a legal opinion or a substitute for counsel's review.

## Provenance statements

- ARTEMIS code is maintained in this repository. The implementation register records Cairn and ARTEX as architectural/reference material for dispatcher protocols, evidence workflow, graph/state modeling and orchestration patterns.
- The current project register states that no upstream source code has been copied into ARTEMIS. This is a maintainer assertion, not an independently proven source-code similarity analysis.
- Before distributing a release, preserve the original upstream notices and terms for any reference material actually used, record the exact reference URL and retrieval date, and review any code, text, schemas, assets, or tests imported from upstream.
- A reference to a project, architecture, protocol, or public repository does not by itself establish that its license applies to independently written code. Conversely, absence of copied source does not settle every trademark, patent, attribution, or other legal question.

## Required human/legal decision

The following decisions remain **OPEN** and must not be auto-approved by a script:

1. Confirm whether any upstream expression, snippets, generated artifacts, schemas, or test fixtures were copied or adapted beyond general ideas.
2. Review the applicable license texts and project-specific terms for each upstream reference actually incorporated.
3. Decide required notices, attribution, source-offer, copyleft, trademark, and redistribution obligations for the intended distribution model.
4. Have a qualified reviewer approve the release's provenance and license compatibility statement.

## Release gate

Until the above review is recorded with reviewer, date, reviewed references, disposition, and supporting evidence, `ART-LICENSE-001` remains `IN_PROGRESS`. ARTEMIS must not claim that legal compatibility has been certified. The release's own `LICENSE` file does not resolve obligations that could arise from third-party material.
