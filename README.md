# Project Aethelgard

> **Zero-Trust Autonomous Decentralized Swarm (ZT-ADS) Mesh Engine**  
> *Engineered in Java 21+ on Netty NIO with Post-Quantum Cryptography, eBPF Kernel Acceleration, and BFT Swarm Clocks.*

---

## 1. Executive Architecture Overview

Project Aethelgard is a high-throughput, headless agent mesh node built for adversarial and zero-trust operating environments. Rather than relying on centralized cluster coordinators or trusted CA hierarchies, Aethelgard nodes form an emergent, self-governing peer-to-peer mesh that authenticates every frame, scores peer behavior in real time, and executes decentralized quarantine consensus across the network.

### The 7-Layer Autonomous Stack

```
┌────────────────────────────────────────────────────────────────────────┐
│ Layer 7: Time-Triggered Deterministic Gossip Execution (Swarm Clocks)   │
├────────────────────────────────────────────────────────────────────────┤
│ Layer 6: Native Kernel Bridge (Panama FFM / eBPF XDP Hardware Bypass)  │
├────────────────────────────────────────────────────────────────────────┤
│ Layer 5: Post-Quantum Cryptographic Agility (ML-DSA / Crystals Hybrid) │
├────────────────────────────────────────────────────────────────────────┤
│ Layer 4: Byzantine Fault Tolerant Consensus & Quarantine Gossip       │
├────────────────────────────────────────────────────────────────────────┤
│ Layer 3: Autonomous Decision Loop (Virtual Threads / Loom Scorer)      │
├────────────────────────────────────────────────────────────────────────┤
│ Layer 2: In-Memory Ephemeral Identity & Mutual TLS (mTLS Pinning)       │
├────────────────────────────────────────────────────────────────────────┤
│ Layer 1: Reactive Framing & Zero-Copy Netty NIO Transport Pipeline     │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Inbound Data Path & Pipeline Topology

Every socket connection traverses a non-blocking Netty pipeline where framing, decryption, integrity validation, and telemetry scoring execute on worker event loops without copying payload bytes to the JVM heap.

```
                      INBOUND NETWORK PACKET
                                │
                                ▼
                       [ TCP Native Socket ]
                                │
                                ▼
  ┌───────────────────────────────────────────────────────────┐
  │ 1. SslHandler (Layer 2)                                   │
  │    - TLS 1.3 Strict Mutual Authentication (mTLS)          │
  │    - Ephemeral EC P-256 Key Pinning                       │
  │    - Zero-Plaintext Exposure: Handshake starts on active  │
  └─────────────────────────────┬─────────────────────────────┘
                                │ Plaintext Byte Stream
                                ▼
  ┌───────────────────────────────────────────────────────────┐
  │ 2. AethelFrameDecoder (Layer 1)                           │
  │    - Magic Byte Verification: 0xA7 0x48 ('A' 'H')         │
  │    - Length Framing & Maximum Frame Size Guard (16 MiB)   │
  │    - Direct retained slice zero-copy extraction           │
  │    - Malformed/tampered frames feed telemetry sensor      │
  └─────────────────────────────┬─────────────────────────────┘
                                │ Parsed Frame Object
                                ▼
  ┌───────────────────────────────────────────────────────────┐
  │ 3. HybridFrameCodec (Layer 5)                             │
  │    - Dual Signature Verification: Classical + ML-DSA-65   │
  │    - CompositeByteBuf zero-copy buffer slicing            │
  └─────────────────────────────┬─────────────────────────────┘
                                │ Validated Domain Payload
                                ▼
  ┌───────────────────────────────────────────────────────────┐
  │ 4. AgentNodeHandler (Layer 1/3/4)                         │
  │    - Event Loop Execution Guard                           │
  │    - Dispatches to Gossip Engine & Swarm Consensus         │
  │    - Channel registry binding for automated severance     │
  └───────────────────────────────────────────────────────────┘
```

---

## 3. Telemetry Sensor: Lock-Free Bit-Packed Mechanics

Peer scoring inside `PeerTelemetrySensor` uses lock-free atomic primitives to evaluate network behavior with zero object allocations on hot paths.

Each peer maintains an `AtomicLong` encoding telemetry counters into bit-packed 64-bit words:
* **Bits 0–15:** Valid frame counter (up to 65,535 frames per evaluation epoch)
* **Bits 16–31:** Malformed/corrupted frame counter
* **Bits 32–47:** Handshake and protocol violation events
* **Bits 48–63:** Epoch identifier and state flags

```
 63          48 47          32 31          16 15           0
┌──────────────┬──────────────┬──────────────┬──────────────┐
│  Epoch Flag  │  Violations  │  Malformed   │ Valid Frames │
└──────────────┴──────────────┴──────────────┴──────────────┘
```

The Layer 3 autonomous decision loop runs on Project Loom virtual threads, evaluating these bit-packed registers against a decay algorithm:
$$\text{Score}_{t} = (\text{Score}_{t-1} \times \lambda) + \Delta \text{Valid} - (\text{Penalty} \times \Delta \text{Violations})$$
Peers dropping below the critical threshold are automatically nominated for swarm quarantine via Layer 4 gossip.

---

## 4. Building & Running the Project

### Prerequisites
* **Java 21 LTS** or newer (Eclipse Adoptium Temurin recommended)
* **Apache Maven 3.9+** (or use the provided `./mvnw` wrapper)

### Local Build & Automated Tests
Execute the full 53-test integration suite:
```bash
# Using Maven Wrapper (macOS / Linux)
./mvnw clean test

# Using Windows Command Prompt
mvnw.cmd clean test
```

### Build Standalone Fat-JAR
Produce the single, self-contained `target/aethelgard.jar` distribution:
```bash
./mvnw clean package -DskipTests
```

### Running a Local Node Directly
```bash
# Genesis Node
java --enable-preview -jar target/aethelgard.jar --port=8001

# Follower Node connecting to Genesis
java --enable-preview -jar target/aethelgard.jar --port=8002 --connect=127.0.0.1:8001
```

### Consumer One-Click Launchers
For end-users running on local laptops with zero manual configuration:
* **Windows:** Double-click `start-node.bat` (automatically installs Java 21 via winget if missing).
* **macOS / Linux:** Run `./start-node.sh` in terminal.

---

## 5. Dockerized 3-Node Swarm Simulation

Orchestrate a complete 3-node decentralized cluster locally via Docker Compose:

```bash
# Build images and start the 3-node mesh
docker compose up --build

# Inspect swarm logs across all peers
docker compose logs -f

# Terminate the cluster
docker compose down
```

The compose cluster launches:
* **`node-a`** on port `8001` (Genesis peer)
* **`node-b`** on port `8002` (Connected to `node-a`)
* **`node-c`** on port `8003` (Connected to `node-a`)

---

## 6. License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
