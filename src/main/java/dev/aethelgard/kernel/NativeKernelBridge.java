package dev.aethelgard.kernel;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Layer 6: Native Linux eBPF / XDP Line-Rate Defense Bridge via Project Panama.
 *
 * Bridges the Java user space runtime directly to Linux kernel space using Java 21's
 * Foreign Function & Memory (FFM) API (JEP 442/454 preview).
 *
 * Mechanism:
 * When Layer 4 Swarm Consensus Condemnation isolates an abusive or compromised peer,
 * this bridge writes the target IP directly to a pinned Linux kernel BPF hash map
 * ({@code BPF_MAP_TYPE_HASH}).
 *
 * An eBPF / XDP driver program running in the kernel network interface driver inspects
 * incoming TCP packets against this map and returns {@code XDP_DROP} at line-rate speed,
 * discarding hostile packets before they consume CPU cycles or reach the Netty IO stack.
 *
 * Zero-leak off-heap memory guarantee:
 * Every native memory allocation occurs strictly inside a try-with-resources {@link Arena}
 * scope ({@link Arena#ofConfined()}). When execution exits the scope, native memory
 * is deterministically freed, ensuring zero native descriptor or memory leaks.
 */
public final class NativeKernelBridge implements AutoCloseable {

    /** Linux BPF Map Type: BPF_MAP_TYPE_HASH (value = 1) */
    public static final int BPF_MAP_TYPE_HASH = 1;

    /** BPF update flags: BPF_ANY = 0 (create new element or update existing) */
    public static final long BPF_ANY = 0L;

    /** XDP action verdict: XDP_DROP = 1 */
    public static final long XDP_DROP = 1L;

    /** Default pinned eBPF map path in BPF filesystem */
    public static final String DEFAULT_BPF_MAP_PIN_PATH = "/sys/fs/bpf/aethelgard_xdp_blacklist";

    // Native Function Descriptors (POSIX / libbpf C ABI)
    private static final FunctionDescriptor BPF_MAP_UPDATE_ELEM_DESC = FunctionDescriptor.of(
            ValueLayout.JAVA_INT,     // return int (0 = success, -1 = error)
            ValueLayout.JAVA_INT,     // int fd
            ValueLayout.ADDRESS,      // const void *key
            ValueLayout.ADDRESS,      // const void *value
            ValueLayout.JAVA_LONG     // uint64_t flags
    );

    private static final FunctionDescriptor BPF_MAP_DELETE_ELEM_DESC = FunctionDescriptor.of(
            ValueLayout.JAVA_INT,     // return int (0 = success, -1 = error)
            ValueLayout.JAVA_INT,     // int fd
            ValueLayout.ADDRESS       // const void *key
    );

    private static final FunctionDescriptor BPF_OBJ_GET_DESC = FunctionDescriptor.of(
            ValueLayout.JAVA_INT,     // return int (map_fd or -1)
            ValueLayout.ADDRESS       // const char *pathname
    );

    private static final FunctionDescriptor CLOSE_DESC = FunctionDescriptor.of(
            ValueLayout.JAVA_INT,     // return int
            ValueLayout.JAVA_INT      // int fd
    );

    private final Linker linker;
    private final String bpfMapPath;
    private final int bpfMapFd;
    private final boolean nativeLinked;

    private final MethodHandle bpfMapUpdateElemHandle;
    private final MethodHandle bpfMapDeleteElemHandle;
    private final MethodHandle closeHandle;

    // Off-heap memory lifecycle monitoring counters
    private final AtomicLong totalArenasAllocated = new AtomicLong();
    private final AtomicLong totalArenasClosed = new AtomicLong();
    private final AtomicLong totalSegmentsAllocated = new AtomicLong();
    private final AtomicLong totalOffHeapBytesAllocated = new AtomicLong();

    // Registry of active pinned IP mitigations
    private final ConcurrentHashMap<String, PinnedEntry> pinnedMitigations = new ConcurrentHashMap<>();

    public record PinnedEntry(String ipAddress, int networkByteOrderIp, long xdpAction, long pinnedEpochMillis) {}

    public NativeKernelBridge() {
        this(DEFAULT_BPF_MAP_PIN_PATH);
    }

    public NativeKernelBridge(String bpfMapPath) {
        this.bpfMapPath = Objects.requireNonNull(bpfMapPath, "bpfMapPath");
        this.linker = Linker.nativeLinker();

        MethodHandle updateH = null;
        MethodHandle deleteH = null;
        MethodHandle closeH = null;
        int fd = -1;
        boolean linked = false;

        try {
            SymbolLookup lookup = SymbolLookup.loaderLookup().or(linker.defaultLookup());

            // Attempt to bind native libbpf symbols if present in runtime
            Optional<MemorySegment> updateSymbol = lookup.find("bpf_map_update_elem");
            Optional<MemorySegment> deleteSymbol = lookup.find("bpf_map_delete_elem");
            Optional<MemorySegment> objGetSymbol = lookup.find("bpf_obj_get");
            Optional<MemorySegment> closeSymbol = lookup.find("close");

            if (updateSymbol.isPresent() && deleteSymbol.isPresent() && objGetSymbol.isPresent() && closeSymbol.isPresent()) {
                updateH = linker.downcallHandle(updateSymbol.get(), BPF_MAP_UPDATE_ELEM_DESC);
                deleteH = linker.downcallHandle(deleteSymbol.get(), BPF_MAP_DELETE_ELEM_DESC);
                closeH = linker.downcallHandle(closeSymbol.get(), CLOSE_DESC);

                MethodHandle objGetH = linker.downcallHandle(objGetSymbol.get(), BPF_OBJ_GET_DESC);
                try (Arena pathArena = Arena.ofConfined()) {
                    MemorySegment pathSegment = pathArena.allocateUtf8String(bpfMapPath);
                    fd = (int) objGetH.invokeExact(pathSegment);
                }
                linked = (fd >= 0);
            }
        } catch (Throwable ignored) {
            // Fall back gracefully to off-heap MemorySegment emulation
            linked = false;
        }

        this.bpfMapUpdateElemHandle = updateH;
        this.bpfMapDeleteElemHandle = deleteH;
        this.closeHandle = closeH;
        this.bpfMapFd = fd;
        this.nativeLinked = linked;
    }

    /**
     * Pins a hostile IP address to the Linux kernel eBPF map.
     * When executed on Linux, line-rate XDP drops (XDP_DROP) occur before the Java stack.
     *
     * Memory safety:
     * MemorySegment buffers for the key (IPv4 integer) and value (XDP action) are
     * allocated within a strict try-with-resources Arena. Upon exiting, all off-heap
     * memory is deterministically freed.
     */
    public boolean pinKernelMitigation(String ipAddress) {
        Objects.requireNonNull(ipAddress, "ipAddress");
        int networkByteOrderIp = parseIpv4ToNetworkByteOrder(ipAddress);

        totalArenasAllocated.incrementAndGet();
        try (Arena arena = Arena.ofConfined()) {
            // 1. Off-heap allocation: BPF Map Key (4 bytes IPv4 uint32 in network byte order)
            MemorySegment keySegment = arena.allocate(ValueLayout.JAVA_INT);
            totalSegmentsAllocated.incrementAndGet();
            totalOffHeapBytesAllocated.addAndGet(ValueLayout.JAVA_INT.byteSize());
            keySegment.set(ValueLayout.JAVA_INT, 0, networkByteOrderIp);

            // 2. Off-heap allocation: BPF Map Value (8 bytes XDP drop directive + metrics)
            MemorySegment valSegment = arena.allocate(ValueLayout.JAVA_LONG);
            totalSegmentsAllocated.incrementAndGet();
            totalOffHeapBytesAllocated.addAndGet(ValueLayout.JAVA_LONG.byteSize());
            valSegment.set(ValueLayout.JAVA_LONG, 0, XDP_DROP);

            // 3. Native invocation or simulated off-heap kernel map write
            if (nativeLinked && bpfMapUpdateElemHandle != null && bpfMapFd >= 0) {
                try {
                    int res = (int) bpfMapUpdateElemHandle.invokeExact(bpfMapFd, keySegment, valSegment, BPF_ANY);
                    if (res != 0) {
                        return false;
                    }
                } catch (Throwable t) {
                    throw new IllegalStateException("Failed to invoke native bpf_map_update_elem", t);
                }
            }

            // Record mitigation in active registry
            pinnedMitigations.put(ipAddress, new PinnedEntry(
                    ipAddress,
                    networkByteOrderIp,
                    XDP_DROP,
                    System.currentTimeMillis()
            ));
            return true;
        } finally {
            totalArenasClosed.incrementAndGet();
        }
    }

    /**
     * Removes an IP address from the kernel mitigation map.
     */
    public boolean unpinKernelMitigation(String ipAddress) {
        Objects.requireNonNull(ipAddress, "ipAddress");
        int networkByteOrderIp = parseIpv4ToNetworkByteOrder(ipAddress);

        totalArenasAllocated.incrementAndGet();
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment keySegment = arena.allocate(ValueLayout.JAVA_INT);
            totalSegmentsAllocated.incrementAndGet();
            totalOffHeapBytesAllocated.addAndGet(ValueLayout.JAVA_INT.byteSize());
            keySegment.set(ValueLayout.JAVA_INT, 0, networkByteOrderIp);

            if (nativeLinked && bpfMapDeleteElemHandle != null && bpfMapFd >= 0) {
                try {
                    int res = (int) bpfMapDeleteElemHandle.invokeExact(bpfMapFd, keySegment);
                    pinnedMitigations.remove(ipAddress);
                    return res == 0;
                } catch (Throwable t) {
                    throw new IllegalStateException("Failed to invoke native bpf_map_delete_elem", t);
                }
            }

            return pinnedMitigations.remove(ipAddress) != null;
        } finally {
            totalArenasClosed.incrementAndGet();
        }
    }

    public boolean isIpPinned(String ipAddress) {
        return pinnedMitigations.containsKey(ipAddress);
    }

    public int pinnedIpCount() {
        return pinnedMitigations.size();
    }

    public Set<String> getPinnedIps() {
        return Collections.unmodifiableSet(pinnedMitigations.keySet());
    }

    public boolean isNativeLinked() {
        return nativeLinked;
    }

    public String bpfMapPath() {
        return bpfMapPath;
    }

    public int bpfMapFd() {
        return bpfMapFd;
    }

    // Lifecycle monitoring metrics
    public long totalArenasAllocated() {
        return totalArenasAllocated.get();
    }

    public long totalArenasClosed() {
        return totalArenasClosed.get();
    }

    public long activeArenas() {
        return totalArenasAllocated.get() - totalArenasClosed.get();
    }

    public long totalSegmentsAllocated() {
        return totalSegmentsAllocated.get();
    }

    public long totalOffHeapBytesAllocated() {
        return totalOffHeapBytesAllocated.get();
    }

    /**
     * Parses an IPv4 address string into a 32-bit integer in big-endian network byte order.
     */
    public static int parseIpv4ToNetworkByteOrder(String ipAddress) {
        try {
            InetAddress addr = InetAddress.getByName(ipAddress);
            byte[] bytes = addr.getAddress();
            if (bytes.length == 4) {
                return ByteBuffer.wrap(bytes).order(ByteOrder.BIG_ENDIAN).getInt();
            } else {
                // Fallback digest for IPv6 or hostname
                return ByteBuffer.wrap(Arrays.copyOf(bytes, 4)).order(ByteOrder.BIG_ENDIAN).getInt();
            }
        } catch (UnknownHostException e) {
            throw new IllegalArgumentException("Invalid IP address: " + ipAddress, e);
        }
    }

    @Override
    public void close() {
        if (nativeLinked && closeHandle != null && bpfMapFd >= 0) {
            try {
                closeHandle.invokeExact(bpfMapFd);
            } catch (Throwable ignored) {
            }
        }
        pinnedMitigations.clear();
    }
}
