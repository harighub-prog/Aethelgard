package dev.aethelgard.crypto;

import java.net.Socket;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;

/**
 * Runtime-revocable trust engine — the Layer 2 core of the zero-trust design.
 *
 * Instead of a static file-backed trust store, peer admission is delegated to a
 * thread-safe in-memory registry keyed by the SHA-256 of the peer's public key.
 * The Layer 3 BehaviorScorer will call {@link #revoke(PublicKey)} the moment a
 * peer's trust weight hits zero; the very next TLS handshake from that node is
 * rejected at the {@link #checkClientTrusted} gate — no restart, no file edit.
 *
 * Validation performed on every handshake:
 *   1. Expiry + not-yet-valid window (cert.checkValidity)
 *   2. Path integrity: signature verifies against the presented public key
 *      (mesh peers are self-signed, so the chain root must verify itself)
 *   3. Explicit allow-list membership of the peer's public key
 *
 * Any failure throws CertificateException, which the JSSE engine turns into a
 * fatal handshake alert — the socket dies before a single application byte
 * (e.g. an Aethelgard frame) can be exchanged.
 */
public final class AethelgardTrustManager extends X509ExtendedTrustManager {

    /** keyId(PublicKey) -> true. Presence = admitted. Absence = rejected. */
    private final Set<String> trustedKeys = ConcurrentHashMap.newKeySet();

    /* ── Dynamic admission control (Layer 3 hook) ─────────────────────────── */

    /** Admits a peer identity. Idempotent. */
    public void trust(PublicKey peerKey) {
        trustedKeys.add(keyId(peerKey));
    }

    /**
     * Instantly revokes a peer identity. All future TLS handshakes presenting
     * this key fail; existing connections keep running until Layer 4's
     * consensus isolation drops their sockets.
     */
    public void revoke(PublicKey peerKey) {
        trustedKeys.remove(keyId(peerKey));
    }

    public boolean isTrusted(PublicKey peerKey) {
        return trustedKeys.contains(keyId(peerKey));
    }

    /**
     * KeyId-based variants for the Layer 3 decision loop, which tracks peers
     * by the same SHA-256 key identifier ({@link #keyId(PublicKey)}) rather
     * than holding PublicKey references. Same semantics as the typed variants.
     */
    public void admitKeyId(String keyId) {
        trustedKeys.add(keyId);
    }

    public void revokeKeyId(String keyId) {
        trustedKeys.remove(keyId);
    }

    public boolean isTrustedKeyId(String keyId) {
        return trustedKeys.contains(keyId);
    }

    public int trustedPeerCount() {
        return trustedKeys.size();
    }

    /* ── JSSE callbacks (both plain and extended variants) ────────────────── */

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        verify(chain, authType);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        verify(chain, authType);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket)
            throws CertificateException {
        verify(chain, authType);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket)
            throws CertificateException {
        verify(chain, authType);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
            throws CertificateException {
        verify(chain, authType);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
            throws CertificateException {
        verify(chain, authType);
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        // Issuer names are irrelevant in a public-key-pinned mesh: admission is
        // decided by the dynamic registry, so no static issuer list is exposed.
        return new X509Certificate[0];
    }

    /* ── Core verification ─────────────────────────────────────────────────── */

    private void verify(X509Certificate[] chain, String authType) throws CertificateException {
        if (chain == null || chain.length == 0) {
            throw new CertificateException("Empty peer certificate chain");
        }
        X509Certificate leaf = chain[0];

        // 1. Temporal validity — expiry AND not-yet-valid both throw here.
        leaf.checkValidity();

        // 2. Path integrity. Mesh identities are self-signed single-cert chains:
        //    the leaf must verify with its own key. (A longer chain would be
        //    pinned key-first anyway; we reject what we did not admit.)
        try {
            leaf.verify(leaf.getPublicKey());
        } catch (java.security.GeneralSecurityException e) {
            throw new CertificateException("Peer certificate fails integrity verification", e);
        }

        // 3. Dynamic allow-list — the zero-trust gate itself.
        if (!isTrusted(leaf.getPublicKey())) {
            throw new CertificateException(
                    "Peer public key %s is not in the dynamic trust registry".formatted(keyId(leaf.getPublicKey())));
        }
    }

    /** Stable collision-resistant identifier for a public key (the mesh-wide peer identity). */
    public static String keyId(PublicKey key) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(key.getEncoded());
            return Arrays.toString(digest); // deterministic; used only as a map key
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
