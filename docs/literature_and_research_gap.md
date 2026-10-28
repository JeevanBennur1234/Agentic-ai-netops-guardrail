# Literature Survey and Research Gap
Prepared: 2026-10-27

## Purpose

This document verifies the core references named in the Phase 1 presentation and narrows the contribution claim to what this repository actually implements. Bibliographic details below were checked against publisher, conference or institutional records. The final report should use the department's required IEEE citation style consistently.

## Verified references

[1] P. Kazemian, G. Varghese, and N. McKeown, "Header Space Analysis: Static Checking for Networks," in Proceedings of the 9th USENIX Symposium on Networked Systems Design and Implementation (NSDI 12), San Jose, CA, USA, Apr. 2012, pp. 113-126. [Online]. Available: https://www.usenix.org/conference/nsdi12/technical-sessions/presentation/kazemian

[2] A. Khurshid, X. Zou, W. Zhou, M. Caesar, and P. B. Godfrey, "VeriFlow: Verifying Network-Wide Invariants in Real Time," in Proceedings of the 10th USENIX Symposium on Networked Systems Design and Implementation (NSDI 13), Lombard, IL, USA, Apr. 2013. [Online]. Available: https://www.usenix.org/conference/nsdi13/technical-sessions/presentation/khurshid

[3] C. J. Anderson, N. Foster, A. Guha, J.-B. Jeannin, D. Kozen, C. Schlesinger, and D. Walker, "NetKAT: Semantic Foundations for Networks," in Proceedings of the 41st ACM SIGPLAN-SIGACT Symposium on Principles of Programming Languages (POPL), 2014, pp. 113-126, doi: 10.1145/2535838.2535862. [Online]. Available: https://collaborate.princeton.edu/en/publications/netkat-semantic-foundations-for-networks/

[4] P. Alcock, B. Simms, W. Fantom, C. Rotsos, and N. Race, "Improving Intent Correctness with Automated Testing," in Proceedings of the 8th IEEE International Conference on Network Softwarization (NetSoft), 2022, pp. 61-66, doi: 10.1109/NetSoft54395.2022.9844054. [Online]. Available: https://research.lancaster-university.uk/en/publications/improving-intent-correctness-with-automated-testing/

[5] A. Leivadeas and M. Falkner, "A Survey on Intent-Based Networking," IEEE Communications Surveys & Tutorials, vol. 25, no. 1, pp. 625-655, 2023, doi: 10.1109/COMST.2022.3215919. [Online]. Available: https://pure.etsmtl.ca/en/publications/a-survey-on-intent-based-networking/

[6] A. Abane, A. Battou, and M. Merzouki, "An Adaptable AI Assistant for Network Management," in Proceedings of the 2024 IEEE/IFIP Network Operations and Management Symposium (NOMS), Seoul, South Korea, May 2024, doi: 10.1109/NOMS59830.2024.10574957. [Online]. Available: https://www.nist.gov/publications/adaptable-ai-assistant-network-management-0

[7] B. Lantz, B. Heller, and N. McKeown, "A Network in a Laptop: Rapid Prototyping for Software-Defined Networks," in Proceedings of the 9th ACM SIGCOMM Workshop on Hot Topics in Networks (HotNets-IX), 2010, doi: 10.1145/1868447.1868466. [Online]. Available: https://conferences.sigcomm.org/hotnets/2010/papers/a19-lantz.pdf

[8] Ryu SDN Framework, "Component-based software defined networking framework." [Online]. Available: https://ryu-sdn.org/. Accessed: Oct. 27, 2026.

## What this literature supports

- Header Space Analysis provides a static network analysis framework for reachability failures, forwarding loops, and traffic isolation/leakage.
- VeriFlow places an invariant-checking layer between a controller and forwarding devices and checks rule updates in real time.
- NetKAT provides a formal semantic basis for reasoning about network programs, with reachability and non-interference applications.
- Intent-correctness work argues for automated testing, verification and monitoring as first-class parts of intent-based networking.
- Intent-based networking surveys describe closed-loop components such as intent translation, resolution, activation and assurance.
- The cited LLM assistant shows AI support for network management using runtime state/context and knowledge-related techniques.
- Mininet is the emulation environment used here to build reproducible SDN topologies; Ryu provides an OpenFlow controller framework.

## Defensible research gap statement

The sources above do not justify a broad statement that "no open framework independently verifies AI-generated network changes." VeriFlow and other cited network verifiers already perform strong invariant checks in their intended settings.

A narrower, defensible statement for this project is:

"This project prototypes an integration pipeline in which an LLM proposes a structured network-remediation intent, a separate topology-aware guardrail checks a limited set of invariants, a bounded executor applies approved trunk-block actions, and audit/test components record the result. The prototype is evaluated in a Mininet/Ryu/OVS environment, including access-port rejection, paired trunk-rule checks, telemetry-aware reachability checks, audit integrity and failure/rollback experiments."

This statement describes the implementation rather than claiming global novelty. Any claim of novelty beyond integration must be supported by a broader systematic survey and a direct comparison table.

## Research distinction and limitations

The current safety verifier uses a NetworkX graph built from switch, port, link and optional STP state telemetry. It is not equivalent to Header Space Analysis, VeriFlow or NetKAT. It does not symbolically reason over arbitrary OpenFlow match/action rules, packet headers, middleboxes, or all policy constraints.

The current local model is an intent proposer, not a measured anomaly detector. Manual synthetic intents in the experiment suite test the deterministic safety gate; they do not measure the LLM's false-accept rate.

The live active-trunk experiment must be reported honestly: baseline host reachability passed, loss of the active trunk did not lead to a verified alternate forwarding path, and restoring the original trunk restored connectivity. This remains an unresolved engineering and research result.

## Presentation updates

- Slide 4: correct the first author's name to "Peyman Kazemian"; use the full HSA title from [1].
- Slide 4: retain the limitations of each work but avoid presenting them as proof that no open verifier exists.
- Slide 12: replace "sources to be fully cited" with the formatted bibliography above, then use the same reference numbering throughout the report.
- Slides 8 and 10: distinguish implemented software, synthetic tests, successful live integration checks, and unfinished active failover. Do not present active failover as complete.
