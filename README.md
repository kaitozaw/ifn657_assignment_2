# IFN657 Assignment 2

Fuzzing, crash triage and remediation of three targets: `sentinel_network`, `sentinel_payload`, `sentinel_telemetry`.

## Directory Structure

```
.
├── crashes/                 # Representative crash inputs per target
├── exploits/                # Exploit inputs per target
├── images/                  # Screenshots (AFL++ status, stats) per target
├── remediated_src/          # Remediated source code per target
├── seeds/                   # Seed inputs per target
├── sentinel_network/        # Working dir: builds, seeds, dict, findings, crash logs/analysis, remediation
├── sentinel_payload/        # Working dir: builds, seeds, dict, findings, crash logs/analysis, remediation
├── sentinel_telemetry/      # Working dir: builds, seeds, dict, findings, crash logs/analysis, remediation
├── targets/                 # Original target sources and initial seeds
├── as2_report_template.md   # Report template
├── as2.pdf                  # Assignment specification
├── Group_01.md              # Group report
└── README.md                # This document
```