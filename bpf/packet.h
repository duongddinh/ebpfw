/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef EBPFW_PACKET_H
#define EBPFW_PACKET_H
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;

#define MAX_RULES 64
#define DROP 1
#define PASS 2
struct rule {
    u8 action, family, proto, reserved;
    u16 port_low, port_high;
    u32 prefix_len;
    u8 source[16];
};
struct policy {
    u32 count, default_action;
    struct rule rules[MAX_RULES];
};
struct packet {
    u8 source[16];
    u16 port;
    u8 family, proto;
};

static __inline __attribute__((always_inline)) u16 read16(const u8 *p)
{
    return ((u16)p[0] << 8) | p[1];
}

/* 0 = non-IP, 1 = parsed IP, -1 = malformed or deliberately unsupported.
 * All fragments and IPv6 extension headers are dropped to prevent rules
 * being bypassed through transport headers outside the parsed region. */
static __inline __attribute__((always_inline)) int parse_packet(
    const u8 *data, const u8 *end, struct packet *p)
{
    if (data + 14 > end)
        return -1;
    u32 offset = 14;
    u16 ether_type = read16(data + 12);
#pragma unroll
    for (int i = 0; i < 2; i++) {
        if (ether_type == 0x8100 || ether_type == 0x88a8) {
            if (data + offset + 4 > end)
                return -1;
            ether_type = read16(data + offset + 2);
            offset += 4;
        }
    }
    if (ether_type == 0x8100 || ether_type == 0x88a8)
        return -1;
    const u8 *ip = data + offset;
    u32 transport;
    u32 ip_length;
    if (ether_type == 0x0800) {
        if (ip + 20 > end || (ip[0] >> 4) != 4)
            return -1;
        u32 ihl = (ip[0] & 15) * 4;
        ip_length = read16(ip + 2);
        if (ihl < 20 || ip_length < ihl || ip + ip_length > end || ip + ihl > end)
            return -1;
        if (read16(ip + 6) & 0x3fff)
            return -1;
        p->family = 4;
        p->proto = ip[9];
        __builtin_memcpy(p->source, ip + 12, 4);
        transport = offset + ihl;
    } else if (ether_type == 0x86dd) {
        if (ip + 40 > end || (ip[0] >> 4) != 6)
            return -1;
        ip_length = 40 + read16(ip + 4);
        if (ip + ip_length > end)
            return -1;
        p->family = 6;
        p->proto = ip[6];
        __builtin_memcpy(p->source, ip + 8, 16);
        transport = offset + 40;
        /* Hop-by-hop, routing, fragment, ESP, AH, destination, mobility,
         * HIP, Shim6 and experimental extension headers. */
        if (p->proto == 0 || p->proto == 43 || p->proto == 44 ||
            p->proto == 50 || p->proto == 51 || p->proto == 60 ||
            p->proto == 135 || p->proto == 139 || p->proto == 140 ||
            p->proto == 253 || p->proto == 254)
            return -1;
    } else {
        return 0;
    }
    const u8 *l4 = data + transport;
    u32 remaining = offset + ip_length - transport;
    if (p->proto == 6) {
        if (remaining < 20 || l4 + 20 > end)
            return -1;
        u32 length = (l4[12] >> 4) * 4;
        if (length < 20 || length > remaining || l4 + length > end)
            return -1;
        p->port = read16(l4 + 2);
    } else if (p->proto == 17) {
        if (remaining < 8 || l4 + 8 > end)
            return -1;
        u16 length = read16(l4 + 4);
        if (length < 8 || length > remaining)
            return -1;
        p->port = read16(l4 + 2);
    } else if (p->proto == 1 || p->proto == 58) {
        if (remaining < 8 || l4 + 8 > end ||
            (p->proto == 1 && p->family != 4) ||
            (p->proto == 58 && p->family != 6))
            return -1;
    }
    return 1;
}

static __inline __attribute__((always_inline)) int rule_matches(
    const struct rule *r, const struct packet *p)
{
    if (r->family && r->family != p->family)
        return 0;
    if (r->proto && r->proto != p->proto)
        return 0;
    if (r->port_low && (p->port < r->port_low || p->port > r->port_high))
        return 0;
#pragma unroll
    for (int i = 0; i < 16; i++) {
        if (r->prefix_len > (u32)i * 8) {
            u32 bits = r->prefix_len - i * 8;
            u8 mask = bits >= 8 ? 255 : (u8)(255 << (8 - bits));
            if ((r->source[i] & mask) != (p->source[i] & mask))
                return 0;
        }
    }
    return 1;
}
#endif
