# Project Aethelgard: Engineering Contribution Guidelines

Welcome to the Project Aethelgard core infrastructure codebase. Because Aethelgard is a zero-trust, high-throughput autonomous mesh operating in hostile network topologies, all contributed code must adhere to uncompromising performance and thread-safety invariants.

---

## 1. Core Engineering Principles

1. **Zero-Heap-Allocation Hot Paths:**  
   Code executing on Netty I/O worker threads or telemetry sampling loops must never allocate intermediate heap objects (`byte[]`, boxing wrappers, unnecessary lambdas). Leverage direct buffers, `ByteBuf.readRetainedSlice()`, and primitive atomic registers.
2. **Deterministic Verification:**  
   Every pull request must maintain 100% test pass rate across the JUnit test suite (`mvn clean test`). Regressions in memory leak detection or frame decoding will result in automated rejection.
3. **No External Storage Dependencies:**  
   Nodes are completely self-contained. Do not introduce dependencies on local disk caches, relational databases, or external coordination services (ZooKeeper, etcd).

---

## 2. Concurrency & Thread-Safety Standards

### The Event-Loop Thread Affinity Rule
* Handlers extending `ChannelInboundHandlerAdapter` or `ByteToMessageDecoder` execute strictly within the thread context of their assigned Netty `EventLoop`.
* **Never perform blocking operations** (synchronous disk I/O, `Thread.sleep()`, long lock acquisition) inside an event loop thread.
* Long-running computational tasks (such as background scoring or quarantine evaluation) must run on **Project Loom virtual threads** (`Thread.ofVirtual()`), decoupled from the network I/O loop.

### The Event-Loop Byte Snapshotting Rule
When an event-loop handler needs to dispatch payload data to an asynchronous background worker or virtual thread:
1. **Never pass a mutable `ByteBuf` across thread boundaries** without explicit reference count governance.
2. If the recipient outlives the channel read pipeline cycle, extract a retained direct slice via `ByteBuf.retainedSlice()` or take an immutable slice snapshot before dispatching.
3. The consuming thread assumes sole responsibility for calling `ReferenceCountUtil.release()` upon completion.

---

## 3. Cryptographic Standards

* **No Weak Ciphers:** Only TLS 1.3 cipher suites (`TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`) and quantum-safe algorithms (ML-DSA-65 / Dilithium5) are permitted.
* **Pure In-Memory PKI:** Keys and certificates must remain in memory. Never write private keys, certificates, or keystores to disk.
* **Deterministic Seeds:** In tests, cryptographic operations must utilize cryptographically secure randomness or explicit test vectors without degrading production entropy sources.

---

## 4. Submitting Pull Requests

1. **Format:** Code must adhere to standard Java conventions, 4-space indentation, and LF line endings.
2. **Review Checklist:**
   - [ ] Does the change compile with `--enable-preview` under Java 21?
   - [ ] Are all direct buffer allocations balanced with appropriate releases?
   - [ ] Does `mvn test` pass with `-Dio.netty.leakDetection.level=paranoid`?
   - [ ] Are all public APIs documented with comprehensive Javadocs?
