package dev.aethelgard.gossip;

import dev.aethelgard.crypto.AethelgardTrustManager;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.IntSupplier;

/**
 * Swarm consensus judgment. Tracks VERIFIED ballots per target key-ID and
 * applies the Absolute Majority Rule:
 *
 *     consensus ⟺ distinctNominators(target) > clusterSize / 2
 *
 * clusterSize is supplied live (admitted peers + self) so membership changes
 * are reflected without restart. Each nominator counts ONCE regardless of how
 * many ballots it signed (dedupe on nominatorId, not ballotId).
 *
 * On consensus — exactly once per target (AtomicBoolean fence):
 *   1. Revoke the key-ID in the AethelgardTrustManager (future sessions die).
 *   2. Sever every live channel bound to that key-ID (via the Severance
 *      callback, implemented by the GossipEngine which owns the channel map).
 *   3. Append the peer's remote IPs to the network blacklist; any future
 *      connection from a blacklisted IP is refused at channelActive.
 *
 * Thread-safety: all state is concurrent collections; judgment and execution
 * are idempotent under racing submissions — losers of the AtomicBoolean see
 * isIsolated=true and skip re-execution.
 */
public final class ConsensusRegistry {

    /** Execution hook: drops all live channels for the target key-ID. */
    public interface Severance {
        void severChannelsFor(String targetKeyId);
    }

    private final AethelgardTrustManager trustManager;
    private final IntSupplier clusterSize;
    private volatile Severance severance;   // bound post-construction (engine circularity)

    /** targetKeyId → verified distinct nominatorIds. */
    private final ConcurrentHashMap<String, Set<String>> nominatorsByTarget = new ConcurrentHashMap<>();
    /** targetKeyId → isolation already executed (fence). */
    private final ConcurrentHashMap<String, AtomicBoolean> isolationFlags = new ConcurrentHashMap<>();
    /** Low-level network blacklist: remote IPs of condemned peers. */
    private final Set<String> blacklistedIps = new CopyOnWriteArraySet<>();
    /** key-IDs formally condemned by consensus (identity-level blacklist). */
    private final Set<String> condemnedKeys = new CopyOnWriteArraySet<>();

    private volatile dev.aethelgard.kernel.NativeKernelBridge kernelBridge;

    public ConsensusRegistry(AethelgardTrustManager trustManager,
                             IntSupplier clusterSize,
                             Severance severance) {
        this(trustManager, clusterSize, severance, null);
    }

    public ConsensusRegistry(AethelgardTrustManager trustManager,
                             IntSupplier clusterSize,
                             Severance severance,
                             dev.aethelgard.kernel.NativeKernelBridge kernelBridge) {
        this.trustManager = trustManager;
        this.clusterSize = clusterSize;
        this.severance = severance;
        this.kernelBridge = kernelBridge;
    }

    /**
     * Records a VERIFIED ballot. Returns true if this submission is the one
     * that achieved consensus (i.e., execution ran during this call).
     * Callers must only submit ballots that passed QuarantineBallot.verify().
     */
    public boolean record(QuarantineBallot ballot) {
        String target = ballot.targetKeyId();
        AtomicBoolean executed = isolationFlags.computeIfAbsent(target, k -> new AtomicBoolean(false));
        if (executed.get()) {
            return false; // already condemned; nothing to count toward
        }
        Set<String> nominators = nominatorsByTarget.computeIfAbsent(target, k -> new CopyOnWriteArraySet<>());
        nominators.add(ballot.nominatorId());

        int cluster = clusterSize.getAsInt();
        if (nominators.size() > cluster / 2.0) {
            if (executed.compareAndSet(false, true)) {
                executeIsolation(target, ballot);
                return true;
            }
        }
        return false;
    }

    private void executeIsolation(String target, QuarantineBallot trigger) {
        condemnedKeys.add(target);
        // 1. Identity gate: every future TLS session for this key dies.
        trustManager.revokeKeyId(target);
        // 2. Active severance: drop live sockets bound to the key-ID.
        Severance sev = severance;
        if (sev != null) {
            sev.severChannelsFor(target);
        }
        // 3. IP blacklist is populated by the engine (it owns the remote
        //    addresses of the severed channels) — see blacklistIp().
        System.out.printf("[ConsensusRegistry] CONSENSUS: %s isolated (%d nominators, cluster=%d, trigger=%s)%n",
                abbreviate(target), nominatorsByTarget.get(target).size(), clusterSize.getAsInt(),
                abbreviate(trigger.nominatorId()));
    }

    /** Two-phase binding: breaks the engine ↔ registry construction cycle. */
    public void bindSeverance(Severance severance) {
        this.severance = severance;
    }

    /** Binds Layer 6 NativeKernelBridge for eBPF/XDP line-rate defense. */
    public void bindKernelBridge(dev.aethelgard.kernel.NativeKernelBridge kernelBridge) {
        this.kernelBridge = kernelBridge;
    }

    public dev.aethelgard.kernel.NativeKernelBridge kernelBridge() {
        return kernelBridge;
    }

    /** Called by the engine while severing: append a condemned peer's IP and pin to kernel map. */
    public void blacklistIp(String ip) {
        blacklistedIps.add(ip);
        dev.aethelgard.kernel.NativeKernelBridge bridge = this.kernelBridge;
        if (bridge != null) {
            bridge.pinKernelMitigation(ip);
        }
    }

    public boolean isIpBlacklisted(String ip) {
        return blacklistedIps.contains(ip);
    }

    public boolean isCondemned(String targetKeyId) {
        return condemnedKeys.contains(targetKeyId);
    }

    public int nominatorCount(String targetKeyId) {
        Set<String> n = nominatorsByTarget.get(targetKeyId);
        return n == null ? 0 : n.size();
    }

    private static String abbreviate(String id) {
        return id.length() <= 12 ? id : id.substring(0, 12) + "…";
    }
}
