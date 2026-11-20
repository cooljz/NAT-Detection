/*
 * NAT behavior discovery per RFC 4787 / RFC 5780 (UDP, IPv4, C99 + POSIX sockets).
 *
 * Build: cc -O2 -Wall -Wextra -o nat_detect nat_detect.c
 * Usage: ./nat_detect [host[:port]]
 *
 * The STUN server must support RFC 5780 (OTHER-ADDRESS and CHANGE-REQUEST).
 */
#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define MAGIC 0x2112A442u
#define BINDING_REQUEST 0x0001
#define BINDING_SUCCESS 0x0101
#define ATTR_MAPPED 0x0001
#define ATTR_CHANGE_REQUEST 0x0003
#define ATTR_CHANGED_ADDRESS 0x0005 /* RFC 3489 name for OTHER-ADDRESS */
#define ATTR_XOR_MAPPED 0x0020
#define ATTR_OTHER_ADDRESS 0x802C
#define FLAG_CHANGE_IP 0x04u
#define FLAG_CHANGE_PORT 0x02u

#define DEFAULT_SERVER "stunserver2025.stunprotocol.org:3478"

enum behavior { UNKNOWN = 0, EI, AD, APD };

static const char *behavior_name(enum behavior b) {
    switch (b) {
    case EI: return "Endpoint-Independent";
    case AD: return "Address-Dependent";
    case APD: return "Address and Port-Dependent";
    default: return NULL;
    }
}

/* Addresses are kept in host byte order. */
struct addr {
    uint32_t ip;
    uint16_t port;
};

struct reply {
    struct addr mapped;
    struct addr other;
    int has_other;
};

static void die(const char *msg) {
    fprintf(stderr, "%s\n", msg);
    exit(1);
}

static const char *addr_str(struct addr a, char *buf, size_t len) {
    char ip[INET_ADDRSTRLEN];
    struct in_addr in = {.s_addr = htonl(a.ip)};
    inet_ntop(AF_INET, &in, ip, sizeof ip);
    snprintf(buf, len, "%s:%u", ip, (unsigned)a.port);
    return buf;
}

static int same(struct addr a, struct addr b) { return a.ip == b.ip && a.port == b.port; }

static uint16_t rd16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static uint32_t rd32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}
static void wr16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static void wr32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v;
}

/* Decode an IPv4 (XOR-)MAPPED-ADDRESS style value. */
static int parse_addr(const uint8_t *v, size_t len, int xor_, struct addr *out) {
    if (len < 8 || v[1] != 1) return 0;
    uint16_t port = rd16(v + 2);
    uint32_t ip = rd32(v + 4);
    if (xor_) {
        port ^= (uint16_t)(MAGIC >> 16);
        ip ^= MAGIC;
    }
    out->ip = ip;
    out->port = port;
    return 1;
}

/* Parse a Binding Success Response whose transaction ID matches; 1 on success. */
static int parse_reply(const uint8_t *data, size_t n, const uint8_t txid[12], struct reply *r) {
    if (n < 20 || rd16(data) != BINDING_SUCCESS || rd32(data + 4) != MAGIC || memcmp(data + 8, txid, 12) != 0)
        return 0;
    size_t end = 20 + rd16(data + 2);
    if (end > n) end = n;
    struct addr xor_mapped, plain_mapped;
    int have_xor = 0, have_plain = 0;
    r->has_other = 0;
    size_t pos = 20;
    while (pos + 4 <= end) {
        uint16_t type = rd16(data + pos);
        size_t len = rd16(data + pos + 2);
        if (pos + 4 + len > end) break;
        const uint8_t *v = data + pos + 4;
        if (type == ATTR_XOR_MAPPED) have_xor = parse_addr(v, len, 1, &xor_mapped);
        else if (type == ATTR_MAPPED) have_plain = parse_addr(v, len, 0, &plain_mapped);
        else if (type == ATTR_OTHER_ADDRESS || type == ATTR_CHANGED_ADDRESS)
            r->has_other = parse_addr(v, len, 0, &r->other);
        pos += 4 + ((len + 3) & ~(size_t)3); /* attributes are padded to 4 bytes */
    }
    if (have_xor) r->mapped = xor_mapped;
    else if (have_plain) r->mapped = plain_mapped;
    else return 0;
    return 1;
}

static void random_bytes(uint8_t *buf, size_t n) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f || fread(buf, 1, n, f) != n) die("cannot read /dev/urandom");
    fclose(f);
}

static long ms_left(const struct timespec *deadline) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (deadline->tv_sec - now.tv_sec) * 1000L + (deadline->tv_nsec - now.tv_nsec) / 1000000L;
}

/*
 * Send a Binding Request and wait for a matching reply (1 s per try).
 * The socket is unconnected, so replies from another IP/port are accepted.
 */
static int transact(int fd, struct addr dst, uint32_t flags, int tries, struct reply *out) {
    uint8_t req[28], txid[12], buf[2048];
    size_t req_len = 20;
    random_bytes(txid, sizeof txid);
    wr16(req, BINDING_REQUEST);
    wr16(req + 2, flags ? 8 : 0);
    wr32(req + 4, MAGIC);
    memcpy(req + 8, txid, sizeof txid);
    if (flags) {
        wr16(req + 20, ATTR_CHANGE_REQUEST);
        wr16(req + 22, 4);
        wr32(req + 24, flags);
        req_len = 28;
    }
    struct sockaddr_in to = {.sin_family = AF_INET, .sin_port = htons(dst.port), .sin_addr.s_addr = htonl(dst.ip)};
    for (int i = 0; i < tries; i++) {
        if (sendto(fd, req, req_len, 0, (struct sockaddr *)&to, sizeof to) < 0) return 0;
        struct timespec deadline;
        clock_gettime(CLOCK_MONOTONIC, &deadline);
        deadline.tv_sec += 1;
        for (;;) {
            long left = ms_left(&deadline);
            if (left <= 0) break;
            struct pollfd p = {.fd = fd, .events = POLLIN};
            if (poll(&p, 1, (int)left) <= 0) break;
            ssize_t n = recvfrom(fd, buf, sizeof buf, 0, NULL, NULL);
            if (n < 0) break;
            if (parse_reply(buf, (size_t)n, txid, out)) return 1;
        }
    }
    return 0;
}

static int open_socket(void) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in any = {.sin_family = AF_INET};
    if (fd < 0 || bind(fd, (struct sockaddr *)&any, sizeof any) < 0) die("cannot open socket");
    return fd;
}

static uint16_t local_port(int fd) {
    struct sockaddr_in sa;
    socklen_t len = sizeof sa;
    return getsockname(fd, (struct sockaddr *)&sa, &len) == 0 ? ntohs(sa.sin_port) : 0;
}

/* Local IPv4 address the OS would use to reach the server; 0 if unknown. */
static uint32_t local_ip(struct addr server) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in to = {.sin_family = AF_INET, .sin_port = htons(server.port), .sin_addr.s_addr = htonl(server.ip)};
    struct sockaddr_in me;
    socklen_t len = sizeof me;
    uint32_t ip = 0;
    if (fd >= 0 && connect(fd, (struct sockaddr *)&to, sizeof to) == 0 &&
        getsockname(fd, (struct sockaddr *)&me, &len) == 0)
        ip = ntohl(me.sin_addr.s_addr);
    if (fd >= 0) close(fd);
    return ip;
}

/* RFC 5780 section 4.3. Uses one socket for every probe. */
static enum behavior detect_mapping(int fd, struct addr server, struct addr mapped1, struct addr other) {
    struct reply r2, r3;
    struct addr alt_ip = {other.ip, server.port}; /* other IP, primary port */
    if (!transact(fd, alt_ip, 0, 3, &r2)) return UNKNOWN;
    if (same(r2.mapped, mapped1)) return EI;
    if (!transact(fd, other, 0, 3, &r3)) return UNKNOWN; /* other IP, other port */
    return same(r3.mapped, r2.mapped) ? AD : APD;
}

/*
 * RFC 5780 section 4.4. Uses a fresh socket so earlier probes cannot have
 * opened the filter toward the server's alternate address.
 */
static enum behavior detect_filtering(struct addr server) {
    struct reply r;
    enum behavior result;
    int fd = open_socket();
    if (!transact(fd, server, 0, 3, &r)) result = UNKNOWN;
    else if (transact(fd, server, FLAG_CHANGE_IP | FLAG_CHANGE_PORT, 2, &r)) result = EI;
    else if (transact(fd, server, FLAG_CHANGE_PORT, 2, &r)) result = AD;
    else result = APD;
    close(fd);
    return result;
}

static const char *legacy_name(enum behavior mapping, enum behavior filtering) {
    if (mapping == UNKNOWN || filtering == UNKNOWN) return "unknown";
    if (mapping != EI) return "symmetric";
    return filtering == EI ? "full cone" : filtering == AD ? "restricted cone" : "port-restricted cone";
}

int main(int argc, char **argv) {
    const char *arg = argc > 1 ? argv[1] : DEFAULT_SERVER;
    char host[256], msg[300];
    const char *colon = strrchr(arg, ':');
    size_t host_len = colon ? (size_t)(colon - arg) : strlen(arg);
    long port = 3478;
    if (host_len == 0 || host_len >= sizeof host) die("invalid server address");
    memcpy(host, arg, host_len);
    host[host_len] = '\0';
    if (colon) {
        char *end;
        port = strtol(colon + 1, &end, 10);
        if (*end != '\0' || end == colon + 1 || port < 1 || port > 65535) die("invalid port");
    }

    struct addrinfo hints = {.ai_family = AF_INET, .ai_socktype = SOCK_DGRAM}, *res;
    if (getaddrinfo(host, NULL, &hints, &res) != 0 || !res) {
        snprintf(msg, sizeof msg, "cannot resolve %s", arg);
        die(msg);
    }
    struct addr server = {ntohl(((struct sockaddr_in *)res->ai_addr)->sin_addr.s_addr), (uint16_t)port};
    freeaddrinfo(res);

    int fd = open_socket();
    struct reply first;
    char buf[64];
    if (!transact(fd, server, 0, 3, &first)) {
        snprintf(msg, sizeof msg, "no STUN reply from %s", addr_str(server, buf, sizeof buf));
        die(msg);
    }
    printf("Server:  %s\n", addr_str(server, buf, sizeof buf));
    printf("Mapped:  %s\n", addr_str(first.mapped, buf, sizeof buf));
    if (first.mapped.ip == local_ip(server) && first.mapped.port == local_port(fd))
        puts("Note:    mapped address equals local address, so no NAT was detected.");
    if (!first.has_other)
        die("The server did not send OTHER-ADDRESS, so it does not support RFC 5780. "
            "Use a server that does (for example coturn or stunserver2025.stunprotocol.org).");

    enum behavior mapping = detect_mapping(fd, server, first.mapped, first.other);
    close(fd);
    enum behavior filtering = detect_filtering(server);
    printf("Mapping behavior:   %s\n", behavior_name(mapping) ? behavior_name(mapping) : "unknown (no reply from alternate address)");
    printf("Filtering behavior: %s\n", behavior_name(filtering) ? behavior_name(filtering) : "unknown (no reply)");
    printf("Legacy name (approximate): %s\n", legacy_name(mapping, filtering));
    return 0;
}
