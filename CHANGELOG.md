# Changelog

All notable changes to Project Aethelgard will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] - 2026-10-11

### Added
- **Layer 5 (Post-Quantum Cryptographic Agility):**
  - Integrated NIST FIPS 204 ML-DSA-65 and Dilithium algorithms alongside classical NIST P-256 ECDSA.
  - Implemented `CryptoAgilityEngine` and `DefaultCryptoAgilityEngine` providing dual-signature validation.
  - Developed `HybridFrameCodec` using Netty `CompositeByteBuf` for zero-heap hybrid frame serialization.
- **Layer 6 (Native Kernel Bridge):**
  - Implemented `NativeKernelBridge` leveraging Java 21 Project Panama Foreign Function & Memory (FFM) API.
  - Bound native Linux eBPF / XDP map insertion (`/sys/fs/bpf/aethelgard_xdp_blacklist`) for hardware-level packet drop.
  - Added seamless user-space fallback for Windows, macOS, and environments without `libbpf`.
- **Layer 7 (Time-Triggered Deterministic Gossip Execution):**
  - Created `SwarmEpochManager` tracking localized swarm time offsets using lock-free `AtomicLong` CAS primitives.
  - Implemented Trust-Weighted Fault-Tolerant Average (WTFA) clock convergence algorithm resisting Byzantine clock-skew attacks.
  - Developed `DeterministicTimeTrigger` providing thread-safe, atomic boundary acquisition for scheduled gossip evaluation cycles.
- **Production Packaging & Orchestration:**
  - Added `AgentApp` main entry point with graceful virtual-thread shutdown hook.
  - Added multi-stage `Dockerfile` producing non-root Alpine JRE 21 containers.
  - Added localized 3-node `docker-compose.yml` mesh cluster simulation.
  - Added cross-platform one-click launchers `start-node.bat` (Windows) and `start-node.sh` (macOS/Linux).
  - Added Linux production `deploy/aethelgard.service` with automatic crash restart.

---

## [0.3.0] - 2026-10-09

### Added
- **Layer 3 (Autonomous Decision Loop & Scoring):**
  - Built `PeerTelemetrySensor` with lock-free 64-bit packed atomic telemetry words.
  - Implemented exponential decay scoring algorithm tracking valid frames, malformations, and protocol violations.
  - Designed `DefaultDecisionLoop` operating on Project Loom virtual threads (`Thread.ofVirtual()`).
- **Layer 4 (Byzantine Quarantine Consensus & Gossip):**
  - Implemented `QuarantineBallot` with tamper-proof Ed25519 digital signatures.
  - Implemented anti-entropy push gossip engine (`GossipEngine`) with randomized fan-out routing.
  - Created `ConsensusRegistry` enforcing the Absolute Majority Rule ($N/2 + 1$) for automatic peer severance.

---

## [0.2.0] - 2026-10-08

### Added
- **Layer 2 (In-Memory Ephemeral Identity & Mutual TLS):**
  - Developed `CryptoMaterialGenerator` synthesizing EC P-256 keys and self-signed X.509v3 certificates entirely in-memory.
  - Implemented `AethelgardTrustManager` enforcing public key fingerprint pinning with empty `getAcceptedIssuers()`.
  - Configured `TlsContextFactory` with strict TLS 1.3 mutual authentication (mTLS) and session resumption bypass.

---

## [0.1.0] - 2026-10-07

### Added
- **Layer 1 (Reactive Framing & Zero-Copy Netty NIO Transport Pipeline):**
  - Designed streaming wire protocol with magic bytes `0xA7 0x48`, 16-byte fixed headers, and 16 MiB payload safety caps.
  - Implemented `AethelFrameDecoder` and `AethelFrameEncoder` using `ByteBuf.readRetainedSlice()` for zero-copy memory transfers.
  - Created `TransportServer` and `TransportClient` using Netty NIO event loops.
  - Built initial suite of loopback and frame corruption unit tests.
