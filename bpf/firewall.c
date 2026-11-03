/* SPDX-License-Identifier: GPL-2.0-only */
#include "packet.h"
#define SEC(name) __attribute__((section(name), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) val *name
#define __array(name, val) val *name[]

struct xdp_md { u32 data, data_end, data_meta, ingress_ifindex, rx_queue_index, egress_ifindex; };
static void *(*bpf_map_lookup_elem)(void *, const void *) = (void *)1;

struct policy_map {
    __uint(type, 2); /* BPF_MAP_TYPE_ARRAY */
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct policy);
};
struct policy_map initial_policy SEC(".maps");
struct {
    __uint(type, 12); /* BPF_MAP_TYPE_ARRAY_OF_MAPS */
    __uint(max_entries, 1);
    __type(key, u32);
    __array(values, struct policy_map);
} active_policy SEC(".maps") = { .values = { [0] = &initial_policy } };

struct {
    __uint(type, 6); /* BPF_MAP_TYPE_PERCPU_ARRAY */
    __uint(max_entries, 3); /* pass, drop, malformed/unsupported */
    __type(key, u32);
    __type(value, u64);
} counters SEC(".maps");

static __inline __attribute__((always_inline)) int verdict(u32 action, u32 key)
{
    u64 *count = bpf_map_lookup_elem(&counters, &key);
    if (count)
        (*count)++;
    return action;
}

SEC("xdp")
int ebpfw(struct xdp_md *ctx)
{
    const u8 *data = (void *)(unsigned long)ctx->data;
    const u8 *end = (void *)(unsigned long)ctx->data_end;
    struct packet packet = {};
    int parsed = parse_packet(data, end, &packet);
    if (parsed < 0)
        return verdict(DROP, 2);
    if (!parsed)
        return verdict(PASS, 0);
    u32 zero = 0;
    void *map = bpf_map_lookup_elem(&active_policy, &zero);
    if (!map)
        return verdict(DROP, 1);
    struct policy *policy = bpf_map_lookup_elem(map, &zero);
    if (!policy)
        return verdict(DROP, 1);
    for (u32 i = 0; i < MAX_RULES; i++) {
        if (i >= policy->count)
            break;
        const struct rule *r = &policy->rules[i];
        if (rule_matches(r, &packet))
            return verdict(r->action == PASS ? PASS : DROP, r->action == PASS ? 0 : 1);
    }
    return verdict(policy->default_action == PASS ? PASS : DROP,
                   policy->default_action == PASS ? 0 : 1);
}
char LICENSE[] SEC("license") = "GPL";
