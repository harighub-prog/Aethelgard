# Project Aethelgard: Technical Architecture Specification

> **Deep-Dive Engineering & Subsystem Manual**  
> *Target Platform: Java 21 LTS (Project Panama FFM, Virtual Threads, ZGC, Netty 4.1)*

---

## 1. Zero-Allocation Memory Path & Buffer Reference Lifecycle

Project Aethelgard operates under a strict **zero-heap-allocation contract** on all high-frequency network paths. Incoming TCP segments are managed strictly off-heap through Netty direct buffers and Project Panama off-heap memory segments.

### Inbound Buffer Reference Counting Boundaries
1. **Netty Cumulation Pipeline:**  
   TCP segments arrive in direct buffers pooled by Netty's `PooledByteBufAllocator`.
2. **Streaming Frame Extraction:**  
   `AethelFrameDecoder` reads length headers and extracts payloads using `ByteBuf.readRetainedSlice(length)`. This increments the reference count of the direct memory slice and advances the reader index of the cumulation buffer without copying data bytes to JVM heap memory.
3. **Pipeline Invariance:**  
   When `AgentNodeHandler` processes a frame, it guarantees ownership transfer. Once consumption or dispatch completes, `ReferenceCountUtil.release(payload)` is invoked exactly once.
4. **Leak Detection Shield:**  
   In test environments, `-Dio.netty.leakDetection.level=paranoid` records sampling call stacks for every allocation. Production runs at `simple` level to achieve maximum network throughput.

---

## 2. Cryptographic Identity & Ephemeral Key-Pinning Stance

### In-Memory PKI Architecture
Traditional TLS architectures rely on certificate authority (CA) root trust stores and X.509 signature chains. Aethelgard completely eliminates static trust stores:
* **Ephemeral Materialization:**  
  At node startup, `CryptoMaterialGenerator` generates a fresh EC P-256 (`secp256r1`) key pair completely in-memory using `SecureRandom`.
* **Programmatic Self-Signed Certificates:**  
  A self-signed X.509v3 certificate is synthesized in-memory via BouncyCastle without touching disk files.
* **Strict Key-Pinning Model (`AethelgardTrustManager`):**  
  The custom `X509TrustManager` implementation maintains an in-memory admitted key set. 

### The Empty `getAcceptedIssuers()` Stance
```java
@Override
public X509Certificate[] getAcceptedIssuers() {
    return new X509Certificate[0];
}
```
In standard TLS implementations, `getAcceptedIssuers()` returns the CA roots acceptable to the server, broadcasting them in the `CertificateRequest` message. In Aethelgard:
1. Returning an empty array prevents information leakage regarding admitted peers.
2. It explicitly disables classical PKI path validation: verification succeeds **only** if the peer's public key SHA-256 fingerprint matches an explicitly admitted identity key in `AethelgardTrustManager`.
3. TLS 1.3 session resumption is intentionally bypassed: every connection renegotiates a fresh ephemeral key exchange.

---

## 3. Layer 5: Post-Quantum Cryptographic Agility

To protect swarm communications against retrospective decryption by quantum adversaries (Harvest-Now-Decrypt-Later attacks), Layer 5 provides hybrid authentication:

### Hybrid Cryptographic Schemes
* **Classical Foundation:** NIST P-256 (ECDSA / secp256r1)
* **Post-Quantum Layer:** NIST FIPS 204 ML-DSA (Module-Lattice-Based Digital Signature Algorithm / Dilithium)
* **Composite Framing:**  
  `HybridFrameCodec` encodes frames using Netty's `CompositeByteBuf`:
  ```
  ┌───────────────┬─────────────────────┬──────────────────┬──────────────┐
  │ Header (16 B) │ Classical Sig (64B) │ ML-DSA Sig (~3KB)│ Payload (N B)│
  └───────────────┴─────────────────────┴──────────────────┴──────────────┘
  ```
  Frames are accepted **if and only if both signatures verify successfully**. A cryptographic failure in either domain triggers immediate channel drop and Layer 3 telemetry penalties.

---

## 4. Layer 6: Native Kernel Bridge (Panama FFM / eBPF Offloading)

Layer 6 provides hardware-accelerated traffic filtering through Linux eBPF (Extended Berkeley Packet Filter) and XDP (eXpress Data Path).

### Java 21 Foreign Function & Memory (FFM) API
Using Project Panama (`java.lang.foreign`), `NativeKernelBridge` interfaces directly with Linux kernel memory without legacy JNI wrappers:
* Binds to `libbpf.so` via `Linker.nativeLinker()` and `SymbolLookup`.
* Directly writes blacklisted IPv4/IPv6 addresses into pinned eBPF maps at `/sys/fs/bpf/aethelgard_xdp_blacklist`.
* Offloaded filtering drops malicious packets at the network interface card (NIC) driver level before the Linux network stack even allocates an `sk_buff`.
* **Graceful Degradation:** When executing on Windows, macOS, or non-eBPF Linux kernels, `NativeKernelBridge` automatically falls back to user-space Netty TCP connection rejection.

---

## 5. Layer 7: Byzantine Fault Tolerant Swarm Clock Convergence

Distributed gossip and deterministic evaluation loops depend on synchronized time across all mesh nodes. Adversaries attempting clock-skew attacks (manipulating local system clocks to delay consensus ballots) are neutralized by Layer 7.

### Trust-Weighted Fault-Tolerant Average (WTFA)
`SwarmEpochManager` continuously computes a localized swarm time offset:
$$T_{\text{swarm}} = T_{\text{local}} + \Delta_{\text{offset}}$$

When peer $i$ transmits a clock sample with skew $S_i$ and trust weight $W_i \in [0.0, 1.0]$:
1. **Outlier Rejection (Byzantine Filter):**  
   If $|S_i| > S_{\text{max}}$ (where $S_{\text{max}} = 5\,000\,000\,000\text{ ns}$), the sample is discarded as adversarial.
2. **Exponentially Weighted Convergence:**  
   $$\Delta_{\text{offset}} \leftarrow \Delta_{\text{offset}} + \alpha \cdot W_i \cdot (S_i - \Delta_{\text{offset}})$$
   where $\alpha = 0.1$ is the convergence damping factor.
3. **Lock-Free Concurrency:**  
   The offset is maintained via atomic CAS primitives (`AtomicLong`), guaranteeing zero locks and sub-microsecond evaluation overhead.
