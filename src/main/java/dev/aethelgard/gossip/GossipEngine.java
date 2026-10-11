package dev.aethelgard.gossip;

import dev.aethelgard.crypto.AethelgardTrustManager;
import dev.aethelgard.protocol.CommandType;
import dev.aethelgard.transport.Frame;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import java.net.InetSocketAddress;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Anti-entropy push gossip for quarantine ballots, plus the channel registry
 * that consensus severance acts on.
 *
 * Lifecycle of a ballot:
 *   1. ORIGIN: Layer 3's DecisionLoop hits QUARANTINE_NOMINATE and calls
 *      {@link #nominate(String)} (decision-loop virtual thread). The engine
 *      signs a ballot, records it, relays to a random subset of live channels.
 *   2. RECEIPT: a peer's GOSSIP frame lands in AgentNodeHandler, which calls
 *      {@link #onBallotReceived(QuarantineBallot, Channel)} on the event loop.
 *      The signature is verified; invalid ballots are dropped silently (they
 *      count as malformed input — the decoder/telemetry already handled the
 *      transport-level ones).
 *   3. COUNTERSIGN: a node that receives its FIRST valid ballot for a target
 *      countersigns — adds its own nomination. The verified ballot chain is
 *      itself evidence; this is what lets the swarm converge on absolute
 *      majority without every node independently observing the attack.
 *   4. RELAY: newly-seen ballots are pushed onward (anti-entropy), excluding
 *      the channel they arrived on. Relays are async writes — never blocking
 *      the event loop.
 *
 * Channel registry: keyId → live channels, populated by AgentNodeHandler on
 * handshake completion, evicted on channelInactive. Severance closes every
 * channel in the set and feeds the peers' remote IPs to the blacklist.
 *
 * Memory: ballots are small fixed-size control messages; encode/decode run on
 * the event loop but allocate only O(ballot) bytes (≈200 B), never
 * proportional to data-path traffic.
 */
public final class GossipEngine implements ConsensusRegistry.Severance {

    /** Max distinct channels each ballot is pushed to per hop. */
    private static final int FANOUT = 4;

    private final KeyPair signingKeys;
    private volatile ConsensusRegistry registry;   // bound post-construction
    private final AethelgardTrustManager trustManager;
    private final AtomicLong sequence = new AtomicLong();

    /** Ballot IDs already seen by this node (dedupe → no re-relay loops). */
    private final Set<String> seenBallots = ConcurrentHashMap.newKeySet();
    /** Targets this node has already nominated (countersign guard). */
    private final Set<String> nominatedTargets = ConcurrentHashMap.newKeySet();
    /** keyId → live channels (the swarm routing + severance topology). */
    private final ConcurrentHashMap<String, Set<Channel>> channelsByKeyId = new ConcurrentHashMap<>();

    public GossipEngine(AethelgardTrustManager trustManager, ConsensusRegistry registry) {
        this.signingKeys = QuarantineBallot.generateSigningKeyPair();
        this.trustManager = trustManager;
        this.registry = registry;
    }

    /** Two-phase binding: breaks the engine ↔ registry construction cycle. */
    public void bindRegistry(ConsensusRegistry registry) {
        this.registry = registry;
    }

    /** Returns the underlying trust manager bound to this engine. */
    public AethelgardTrustManager trustManager() {
        return trustManager;
    }

    /* ── Channel registry (called by AgentNodeHandler, event loop) ────────── */

    public void registerChannel(String keyId, Channel channel) {
        channelsByKeyId.computeIfAbsent(keyId, k -> ConcurrentHashMap.newKeySet()).add(channel);
    }

    public void unregisterChannel(String keyId, Channel channel) {
        Set<Channel> set = channelsByKeyId.get(keyId);
        if (set != null) {
            set.remove(channel);
        }
    }

    public boolean isIpBlacklisted(String ip) {
        return registry.isIpBlacklisted(ip);
    }

    /* ── Ballot origination (decision-loop thread) ─────────────────────────── */

    /** Layer 3 QUARANTINE_NOMINATE callback: sign, judge, disseminate. */
    public void nominate(String targetKeyId) {
        if (registry.isCondemned(targetKeyId) || !nominatedTargets.add(targetKeyId)) {
            return; // already condemned, or we already voted
        }
        QuarantineBallot ballot = QuarantineBallot.sign(targetKeyId, signingKeys, sequence.incrementAndGet());
        registry.record(ballot); // our own vote counts toward majority
        System.out.println("[DBG] nominate target=" + targetKeyId.substring(0, 10) + " channels=" + channelsByKeyId.size());
        relay(ballot, null);
    }

    /* ── Ballot receipt (event-loop thread) ────────────────────────────────── */

    /**
     * Handles a decoded GOSSIP payload. Signature-verified, deduped,
     * countersigned on first sight of a target, judged, and relayed.
     * Returns false if the ballot was invalid or stale.
     */
    public boolean onBallotReceived(QuarantineBallot ballot, Channel arrivedOn) {
        System.out.println("[DBG] recv ballot=" + (ballot == null ? "null" : ballot.ballotId().substring(0, 8)) + " valid=" + (ballot != null && ballot.verify()));
        if (ballot == null || !ballot.verify()) {
            return false; // tampered or malformed: drop, do not relay
        }
        if (registry.isCondemned(ballot.targetKeyId())) {
            return false; // judgment already executed; ring-silence
        }
        if (!seenBallots.add(ballot.ballotId())) {
            return true; // duplicate: already processed, do not re-relay
        }
        registry.record(ballot);

        // Countersign: first valid foreign ballot for a target we haven't
        // voted on ourselves adds our nomination to the swarm judgment.
        if (nominatedTargets.add(ballot.targetKeyId())) {
            QuarantineBallot own = QuarantineBallot.sign(
                    ballot.targetKeyId(), signingKeys, sequence.incrementAndGet());
            registry.record(own);
            // The countersignature is NEW information for every peer —
            // including the original ballot's sender, which still needs it to
            // close the majority. Ballot-ID dedupe prevents relay loops.
            relay(own, null);
        }
        relay(ballot, arrivedOn);
        return true;
    }

    /* ── Dissemination ─────────────────────────────────────────────────────── */

    /** Push-relays a ballot to a random subset of live peers. */
    private void relay(QuarantineBallot ballot, Channel exclude) {
        List<Channel> candidates = new ArrayList<>();
        for (Set<Channel> set : channelsByKeyId.values()) {
            candidates.addAll(set);
        }
        candidates.remove(exclude);
        if (candidates.isEmpty()) {
            return;
        }
        // Random subset (fanout): the classic anti-entropy push pattern.
        java.util.Collections.shuffle(candidates, ThreadLocalRandom.current());
        List<Channel> subset = candidates.subList(0, Math.min(FANOUT, candidates.size()));
        byte[] encoded = ballot.encode();
        for (Channel ch : subset) {
            if (ch.isActive()) {
                ByteBuf payload = Unpooled.wrappedBuffer(encoded);
                ch.writeAndFlush(new Frame(CommandType.GOSSIP, payload));
            }
        }
    }

    /* ── Severance execution (ConsensusRegistry.Severance) ─────────────────── */

    /**
     * Drops every live channel bound to the condemned key-ID and blacklists
     * the remote IPs those channels terminated at. Invoked by the registry
     * exactly once per target, at the moment of consensus.
     */
    @Override
    public void severChannelsFor(String targetKeyId) {
        Set<Channel> doomed = channelsByKeyId.remove(targetKeyId);
        if (doomed == null) {
            return;
        }
        for (Channel ch : doomed) {
            if (ch.remoteAddress() instanceof InetSocketAddress addr && addr.getAddress() != null) {
                registry.blacklistIp(addr.getAddress().getHostAddress());
            }
            ch.close(); // asynchronous: never blocks the consensus path
        }
    }
}
