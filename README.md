# Project Cerberus

**The Three-Headed Guardian of the Digital Threshold**

> "Faithful to the shepherd. Relentless against the wolves."

A research initiative exploring biologically inspired, mythologically themed distributed cyber-defense architectures utilizing cooperative AI agents, swarm intelligence, federated decision making, and adaptive network defense.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        YGGDRASIL                                  │
│                   (The Memory Tree)                               │
│         Knowledge Graph: Behaviors, Patterns, Trust, Lineage      │
└─────────────────────────────────────────────────────────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        ▼                     ▼                     ▼
┌───────────────┐    ┌───────────────┐    ┌───────────────┐
│    FENRIR     │    │    GAMR       │    │   ORTHRUS     │
│   (Hunter)    │    │  (Sentinel)   │    │  (Shepherd)   │
│               │    │               │    │               │
│ • Discovery   │───▶│ • Verification│───▶│ • Response    │
│ • Analysis    │    │ • Correlation │    │ • Containment │
│ • Anomaly     │    │ • Consensus   │    │ • Recovery    │
│ • Pathfinding │    │ • Confidence  │    │ • Preservation│
└───────────────┘    └───────────────┘    └───────────────┘
        ▲                     ▲                     ▲
        │                     │                     │
        └─────────────────────┼─────────────────────┘
                              ▼
                   ┌─────────────────────┐
                   │      THE PACK       │
                   │  (Swarm Layer)      │
                   │                     │
                   │ • Workstations      │
                   │ • Servers           │
                   │ • Containers        │
                   │ • IoT Devices       │
                   │ • Network Gear      │
                   └─────────────────────┘
```

## The Three Heads

| Head | Rune | Purpose | Symbol |
|------|------|---------|--------|
| **Fenrir** | Algiz (ᚨ) | Threat discovery, behavioral analysis, anomaly detection, attack chain pathfinding | Protection / Vigilance |
| **Garmr** | Tiwaz (ᛏ) | Verification, correlation, consensus, confidence scoring | Judgment |
| **Orthrus** | Eihwaz (ᛇ) | Response, containment, recovery, evidence preservation | Defense / Endurance |

## The Pack (Swarm Layer)

Every endpoint runs a lightweight node embedding:
- **Watcher** - Local telemetry collection
- **Messenger** - Gossip protocol communication
- **Consensus Client** - Participates in Garmr quorum
- **Policy Engine** - Executes Orthrus directives

## Yggdrasil (The Memory Tree)

Not a management server: a knowledge graph storing:
- Observed behaviors and attack patterns
- Trust scores and environmental baselines
- Threat lineage and behavioral relationships

## Guiding Rules (Architectural Invariants)

1. **No self-propagation** - Agents deployed intentionally, never spread autonomously
2. **No autonomous offensive action** - Defense only
3. **Human override always exists** - Shepherd outranks the hounds
4. **Consensus before containment** - One node cannot quarantine; the pack agrees
5. **Explainability required** - Every action must answer: *Why?*

## Future Research Branches

| Project | Focus |
|---------|-------|
| **Hugin** | Intelligence gathering: threat intel ingestion and synthesis |
| **Munin** | Long-term memory and lessons learned: behavioral history archives |
| **Sköll** | Active pursuit of emerging threats: hunting engine |
| **Hati** | Prediction and forecasting: attack path simulation |
| **Heimdall** | Edge bridge and perimeter observation: the white sentinel at the threshold |
| **Sleipnir** | High-speed inter-agent communication fabric |

## Motto

> **Many Eyes. One Pack. One Flock. Zero Trust Between Them.**

---

## Project Structure

```
cerberus/
├── docs/              # Architecture docs, RFCs, research notes
├── specs/             # Technical specifications (SPEC.md per component)
├── src/
│   ├── fenrir/        # Hunter - telemetry, detection, analysis
│   ├── garmr/         # Sentinel - consensus, correlation, confidence
│   ├── orthrus/       # Shepherd - response, containment, recovery
│   ├── pack/          # Swarm agent - watcher, messenger, consensus, policy
│   └── yggdrasil/     # Knowledge graph - storage, query, lineage
├── tests/             # Unit, integration, simulation tests
├── scripts/           # Operational tooling
└── config/            # Deployment configs, schemas
```

## Lineage

Cerberus sits in the same constellation as:
- **Auralith** - LLM security evaluation & probe harness (feeds Hugin)
- **CaledonAI** - Autonomous agent orchestration (patterns for Pack lifecycle)

## Getting Started

```bash
# TBD - project scaffolding in progress
```

## Licensing & Commercial Deployments

Project Cerberus is distributed under a **Dual-Licensing Model**:

### Community & Research Edition
* The public source code is licensed under the **GNU Affero General Public License v3.0 (AGPLv3)**.
* Independent security researchers, academic institutions, and homelab defense operators are free to inspect, audit, modify, and run Cerberus under AGPLv3 terms. See [LICENSE](LICENSE) for full details.

### Enterprise & Commercial Licensing
* For managed service providers (MSPs), security operations centers (SOCs), hardware appliance integrators, or organizations requiring closed-source deployment, custom SLAs, or proprietary integration without AGPLv3 copyleft obligations:
* **Commercial Proprietary Licenses** are available exclusively through the Project Lead (Rick Metz / Feathercloak).
* Commercial inquiries: `licensing@cerberus.local` (or direct inquiry via Feathercloak).

### Contributions
All outside contributions require acceptance of the [Contributor License Agreement (CLA)](CLA.md). See [CONTRIBUTING.md](CONTRIBUTING.md) for details.