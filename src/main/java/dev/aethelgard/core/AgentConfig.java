package dev.aethelgard.core;

/**
 * Immutable node configuration. Record-based per the project's Java 21 contract.
 *
 * @param bindHost            interface to bind the server socket to (loopback default)
 * @param bindPort            TCP port to bind; 0 = ask the OS for a free ephemeral
 *                            port (tests read back the real port from the channel)
 * @param connectTimeoutMillis outbound peer-connection timeout
 * @param shutdownQuietPeriodMillis quiet period for graceful event-loop shutdown
 */
public record AgentConfig(
        String bindHost,
        int bindPort,
        int connectTimeoutMillis,
        int shutdownQuietPeriodMillis) {

    public AgentConfig {
        if (bindPort < 0 || bindPort > 65535) {
            throw new IllegalArgumentException("bindPort out of range: " + bindPort);
        }
    }

    public static AgentConfig defaults() {
        return new AgentConfig("127.0.0.1", 0, 5_000, 200);
    }

    public AgentConfig withBindPort(int port) {
        return new AgentConfig(bindHost, port, connectTimeoutMillis, shutdownQuietPeriodMillis);
    }
}
