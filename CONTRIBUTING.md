# Contributing to Project Cerberus

Thank you for your interest in contributing to Project Cerberus. Cerberus is an experimental, biologically inspired distributed cyber-defense research initiative exploring cooperative AI agents, swarm intelligence, federated decision making, and adaptive network defense.

---

## 1. Architectural Invariants (Non-Negotiable)

Every contribution must strictly adhere to the five core architectural invariants of Cerberus:

1. **No Self-Propagation:** Agents must always be deployed intentionally by operators. Agents must never autonomously spread, replicate, or pivot across systems.
2. **No Autonomous Offensive Action:** Cerberus is strictly defensive. Agents must never initiate offensive exploits, payload delivery, or retaliatory counter-attacks.
3. **Human Override Authority:** The human operator (The Shepherd) holds absolute override authority over all autonomous nodes, quorums, and hounds.
4. **Consensus Before Containment:** Individual nodes cannot execute quarantine or isolation actions autonomously; decisions require quorum agreement through the Garmr consensus engine.
5. **Full Explainability:** Every alert, verdict, correlation, and containment action must provide a traceable, human-auditable causal explanation ("Why?").

Pull requests that violate any of these invariants will be rejected immediately.

---

## 2. Contributor License Agreement (CLA)

Project Cerberus is developed under a **Dual-Licensing Model**:
* Public, academic, and non-commercial community distributions are licensed under the **GNU Affero General Public License version 3 (AGPLv3)**.
* Enterprise deployments, commercial appliances, and proprietary closed-source integrations are licensed under separate **Commercial Proprietary Licenses** issued exclusively by the Project Lead (Rick Metz / Feathercloak).

To protect the project against copyright fragmentation, prevent third-party appropriation, and ensure the Project Lead retains the legal right to license and commercialize Cerberus in enterprise environments:

**All contributors must accept the [Contributor License Agreement (CLA)](CLA.md) before their pull request can be merged.**

### How to Sign:
When submitting a Pull Request, please ensure that:
1. You review and accept the terms of [CLA.md](CLA.md).
2. You sign off on all git commits using the Developer Certificate of Origin (`git commit -s`), which appends:
   ```text
   Signed-off-by: Your Full Name <your.email@example.com>
   ```
3. If an automated CLA bot is active on the repository, complete the one-click sign-off prompt.

---

## 3. Development Workflow

### Prerequisites
* Rust toolchain (stable, 2024 edition support)
* Protobuf compiler (`protoc`)
* Python 3.12+ (for Shepherd Python harness and data tools)
* Git

### Code Hygiene
Before submitting a pull request, verify that your changes pass all local quality checks:

```bash
# Format Rust code
cargo fmt --all --check

# Run static analysis
cargo clippy --workspace --all-targets -- -D warnings

# Execute test suite
cargo test --workspace
```

### Git Commit Guidelines
* Write clear, imperative commit messages (e.g., `feat(pack): implement mTLS peer discovery handshake`).
* Keep individual commits atomic and focused on a single logical change.
* Include the `-s` / `--signoff` flag on every commit.

---

## 4. Reporting Security Vulnerabilities

If you discover a potential security vulnerability within Cerberus, please do not file a public issue. Instead, report it privately to the maintainers at:

* **Security Contact:** `security@cerberus.local` (or via private GitHub Security Advisory)

We appreciate responsible disclosure and will respond promptly to investigate and remediate reported findings.
