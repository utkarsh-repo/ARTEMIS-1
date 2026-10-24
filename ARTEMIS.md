# ARTEMIS

**Autonomous Application Security Testing Platform**

*Think. Test. Verify.*

ARTEMIS performs bounded, policy-controlled application security checks against explicitly authorized development and staging environments. It combines deterministic HTTP checks, optional AI-assisted planning, application-authored scenarios, OpenAPI inventory, evidence collection, scanner-result imports, and reporting.

## CLI

```bash
python artemis.py --version
python artemis.py --policy policy.json --dry-run
python artemis.py --policy policy.json --run-id staging-001
```

See [README.md](README.md) for setup, policy configuration, supported checks, scenario authoring, operational safety, and reporting details.

ARTEMIS is designed for authorized assessments. Its scope and method policy must be configured for each target; the AI planner cannot bypass those controls or create arbitrary requests.
