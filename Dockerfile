# ─────────────────────────────────────────────────────────────────────────────
# Stage 1: Build
#
# Uses official Eclipse Temurin JDK 21 on Ubuntu Jammy.
# The entire local source tree is compiled inside the build sandbox and
# packaged via maven-shade-plugin into an uber-jar (target/aethelgard.jar).
# ─────────────────────────────────────────────────────────────────────────────
FROM eclipse-temurin:21-jdk-jammy AS build

LABEL stage="aethelgard-build"

# Install Maven 3.9.x for reproducible dependency resolution
RUN apt-get update \
    && apt-get install -y --no-install-recommends maven \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

# Cache dependency layer
COPY pom.xml ./
RUN mvn dependency:go-offline -q

# Copy source tree and compile fat-jar
COPY src/ ./src/
RUN mvn clean package -DskipTests --batch-mode --no-transfer-progress \
    && echo "[Dockerfile] Build complete. Uber-jar:" \
    && ls -lh target/aethelgard.jar

# ─────────────────────────────────────────────────────────────────────────────
# Stage 2: Runtime Execution Wrapper
#
# Minimal Alpine-based Eclipse Temurin JRE 21 execution environment.
# Hardened non-root user execution with zero build tools present.
# ─────────────────────────────────────────────────────────────────────────────
FROM eclipse-temurin:21-jre-alpine AS runtime

LABEL org.opencontainers.image.title="Aethelgard Swarm Mesh Node" \
      org.opencontainers.image.description="7-layer Zero-Trust Autonomous Decentralized Swarm (ZT-ADS) Mesh Node" \
      org.opencontainers.image.version="1.0.0" \
      org.opencontainers.image.vendor="Project Aethelgard Authors"

# Create dedicated unprivileged system account
RUN addgroup -S aethelgard \
    && adduser -S -G aethelgard -H -u 10001 aethelgard

WORKDIR /app

# Copy shaded binary from builder stage
COPY --from=build /workspace/target/aethelgard.jar ./aethelgard.jar

# Switch to unprivileged runtime user
USER aethelgard

# Default container listening port
EXPOSE 8000

# JVM options: Java 21 preview for Project Panama FFM, ZGC for sub-ms pause times
ENTRYPOINT ["java", \
            "--enable-preview", \
            "-Xms64m", \
            "-Xmx256m", \
            "-XX:+UseZGC", \
            "-Xss512k", \
            "-Dio.netty.leakDetection.level=simple", \
            "-Djava.security.egd=file:/dev/urandom", \
            "-jar", "/app/aethelgard.jar"]

# Default argument: bind port 8000 (overridden by compose/CLI)
CMD ["--port=8000"]
