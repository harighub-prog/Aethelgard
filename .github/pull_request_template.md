## Description
<!-- Provide a clear description of the change and its architectural purpose. -->

## Layer Impact
- [ ] Layer 1: Reactive Framing & Netty Transport
- [ ] Layer 2: Ephemeral In-Memory Identity & mTLS
- [ ] Layer 3: Autonomous Decision Loop & Scorer
- [ ] Layer 4: Gossip Engine & Quarantine Consensus
- [ ] Layer 5: Post-Quantum Cryptographic Agility
- [ ] Layer 6: Native Kernel Bridge (Panama FFM / eBPF)
- [ ] Layer 7: Swarm Epoch Manager & BFT Clocks
- [ ] Operational / Packaging / Documentation

## Engineering Checklist
- [ ] Code compiles under Java 21 with `--enable-preview`.
- [ ] All 53 unit and integration tests pass cleanly (`mvn clean test`).
- [ ] Netty Resource Leak Detector passes with zero leaks (`-Dio.netty.leakDetection.level=paranoid`).
- [ ] Zero-heap-allocation contract is maintained on hot I/O paths (direct buffers, retained slices).
- [ ] Javadoc documentation updated for all modified public interfaces.
- [ ] No static keys, credentials, or sensitive artifacts written to disk.
