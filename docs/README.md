# Agentic AI-NetOps Guardrail — Documentation Index

This directory contains the architecture, security specifications, operational runbooks, evaluation data, and reference documentation for the **Agentic AI-NetOps Guardrail** project.

---

## Topical Documentation Map

### Architecture & Security Design
- **[Architecture Overview](architecture_overview.md)**
  Comprehensive explanation of the guardrail pipeline, telemetry collector, formal safety verifier, controlled executor, and tamper-evident cryptographic audit trail.
- **[System Design & Threat Model](system_design_and_threat_model.md)**
  Threat analysis against untrusted AI models, prompt injection, parameter tampering, and network topology isolation, establishing fail-closed mathematical safety guarantees.

### Human-in-the-Loop & Verification
- **[Human Verifier Setup](human_verifier_setup.md)**
  Configuration and lifecycle of HMAC-authenticated operator approval tokens, single-use approval constraints, and out-of-band human control gates.
- **[Issue 2 — Standby Forwarding Containment](issue2_standby_forwarding.md)**
  Specification of dual-trunk redundant topology monitoring, anomalous standby forwarding detection, and safe non-disruptive remediation.

### Operational Runbooks & Demonstrations
- **[Live Demo Runbook](live_demo_runbook.md)**
  Step-by-step operator guide for launching the Ryu SDN controller, Mininet topology, fault injection endpoints, and validating human review through the mission control dashboard.

### Implementation Inventory & Status
- **[Complete Implementation Inventory](PROJECT_COMPLETE_IMPLEMENTATION_INVENTORY.md)**
  Exhaustive inventory of every system component, test suite, safety property, and milestone verification artifact.
- **[Implementation Status](implementation_status.md)**
  Milestone-by-milestone verification records, test suite results, and latency benchmarks.

### Background & Research Context
- **[Literature & Research Gap](literature_and_research_gap.md)**
  Survey of classical network automation, LLM-driven NetOps, and the motivation for deterministic graph verification with cryptographic non-repudiation.
- **[Presentation Update Notes](phase1_presentation_update_notes.md)**
  Milestone briefing notes, technical slide summaries, and project review highlights.
