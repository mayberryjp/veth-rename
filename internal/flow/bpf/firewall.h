// SPDX-License-Identifier: MIT
struct firewall_rule {
    __u8 source[16], destination[16];
    __u16 source_port, destination_port;
    __u8 source_prefix, destination_prefix, family, protocol;
    __u8 direction, action, flags, padding;
    __u32 id;
};

const volatile __u32 firewall_enabled = 0;
const volatile __u32 audit_mode = 0;
const volatile __u32 permit_all_icmp = 1;

struct firewall_table {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, struct firewall_rule);
};

struct firewall_table rule_template SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(max_entries, 1);
    __type(key, __u32);
    __array(values, struct firewall_table);
} rules SEC(".maps") = {
    .values = {
        [0] = &rule_template,
    },
};

struct state_value {
    struct bpf_spin_lock lock;
    __u32 stage;
    __u64 last;
};

// Not LRU: a full table must not evict established connections silently.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct flow_key);
    __type(value, struct state_value);
} connections SEC(".maps");

struct drop_event {
    struct flow_key key;
    __u64 time;
    __u32 rule;
    __u32 octets;
    __u8 direction, reason;
    __u8 padding[6];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1048576);
} drops SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} drop_losses SEC(".maps");

static __noinline int deny(struct flow_key *key, __u8 direction,
                                __u32 rule, __u8 reason, __u32 octets) {
    struct drop_event *event = bpf_ringbuf_reserve(&drops, sizeof(*event), 0);
    if (event) {
        event->key = *key;
        event->time = bpf_ktime_get_ns();
        event->rule = rule;
        event->octets = octets;
        event->direction = direction;
        event->reason = reason;
        __builtin_memset(event->padding, 0, sizeof(event->padding));
        bpf_ringbuf_submit(event, 0);
    } else {
        __u32 index = 0;
        __u64 *count = bpf_map_lookup_elem(&drop_losses, &index);
        if (count)
            *count += 1;
    }
    return audit_mode ? -1 : 2; // TCX_NEXT in audit mode, otherwise TCX_DROP.
}

static __noinline int address_matches(const __u8 *address, const __u8 *network,
                                           __u8 prefix) {
    int matches = 1;
#pragma unroll
    for (int i = 0; i < 16; i++) {
        int bits = (int)prefix - i * 8;
        if (bits > 0) {
            __u8 mask = bits >= 8 ? 255 : (__u8)(255 << (8 - bits));
            if ((address[i] & mask) != network[i])
                matches = 0;
        }
    }
    return matches;
}

static __noinline int rule_matches(struct firewall_rule *r, struct flow_key *k,
                                        __u8 direction) {
    if ((r->direction && r->direction != direction) ||
        (r->family && r->family != k->family) ||
        ((r->flags & 4) && r->protocol != k->protocol))
        return 0;
    int addresses = address_matches(k->source, r->source, r->source_prefix) &&
                    address_matches(k->destination, r->destination, r->destination_prefix);
    if (!addresses && (r->flags & 8))
        addresses = address_matches(k->destination, r->source, r->source_prefix) &&
                    address_matches(k->source, r->destination, r->destination_prefix);
    if (!addresses)
        return 0;
    if ((r->flags & 1) && k->source_port != r->source_port)
        return 0;
    if (r->flags & 2) {
        if (r->flags & 16)
            return k->source_port == r->destination_port || k->destination_port == r->destination_port;
        if (k->destination_port != r->destination_port)
            return 0;
    }
    return 1;
}

static __always_inline void state_key(struct flow_key *out, struct flow_key *key,
                                      __u8 direction, int reverse) {
    *out = *key;
    out->tos = 0;
    out->padding = direction;
    if (reverse) {
        __builtin_memcpy(out->source, key->destination, 16);
        __builtin_memcpy(out->destination, key->source, 16);
        out->source_port = key->destination_port;
        out->destination_port = key->source_port;
        out->padding = direction == 1 ? 2 : 1;
    }
}

static __noinline int established(struct flow_key *key, __u8 direction,
                                       __u8 flags, __u64 now) {
    if (key->protocol != 6 && key->protocol != 17)
        return 0;
    struct flow_key lookup;
    state_key(&lookup, key, direction, 0);
    struct state_value *state = bpf_map_lookup_elem(&connections, &lookup);
    int reverse = 0;
    if (!state) {
        state_key(&lookup, key, direction, 1);
        state = bpf_map_lookup_elem(&connections, &lookup);
        reverse = 1;
    }
    if (!state)
        return 0;
    int allow = 0;
    bpf_spin_lock(&state->lock);
    __u64 timeout = key->protocol == 17 || state->stage == 4 ? 30000000000ULL : 300000000000ULL;
    if (!state->stage || state->stage == 5 || now - state->last > timeout) {
        if (state->stage != 5)
            state->stage = 0;
    } else if (key->protocol == 17) {
        allow = 1;
    } else if (state->stage >= 3 && (flags & 0x14) && !(flags & 2)) {
        allow = 1;
    } else if (reverse && state->stage <= 2 && (flags & 0x17) == 0x12) {
        state->stage = 2;
        allow = 1;
    } else if (!reverse && state->stage == 2 && (flags & 0x16) == 0x10) {
        state->stage = 3;
        allow = 1;
    } else if (!reverse && state->stage == 1 && (flags & 0x17) == 2) {
        allow = 1;
    } else if ((flags & 6) == 4) {
        allow = 1;
    }
    if (allow) {
        state->last = now;
        if (flags & 1)
            state->stage = 4;
        if (flags & 4)
            state->stage = 0;
    }
    bpf_spin_unlock(&state->lock);
    return allow;
}

static __noinline int remember(struct flow_key *key, __u8 direction,
                                    __u8 flags, __u64 now) {
    if (key->protocol != 17 && !(key->protocol == 6 && (flags & 0x17) == 2))
        return 0;
    struct flow_key lookup;
    state_key(&lookup, key, direction, 0);
    struct state_value value = {.stage = 1, .last = now};
    long result = bpf_map_update_elem(&connections, &lookup, &value, BPF_NOEXIST);
    if (result == -17) {
        struct state_value *existing = bpf_map_lookup_elem(&connections, &lookup);
        if (!existing)
            return 1;
        int retiring = 0;
        bpf_spin_lock(&existing->lock);
        if (existing->stage == 5) {
            retiring = 1;
        } else {
            if (!existing->stage || existing->stage >= 3)
                existing->stage = 1;
            existing->last = now;
        }
        bpf_spin_unlock(&existing->lock);
        return retiring;
    }
    return result != 0;
}

struct rule_context {
    struct flow_key key;
    void *table;
    __u32 matched;
    __u8 direction, action;
};

static long find_rule(__u32 index, void *data) {
    struct rule_context *context = data;
    struct firewall_rule *r = bpf_map_lookup_elem(context->table, &index);
    if (!r || !r->id)
        return 1;
    if (r && rule_matches(r, &context->key, context->direction)) {
        context->matched = r->id;
        context->action = r->action;
        return 1;
    }
    return 0;
}

static __noinline int firewall(struct flow_key *key, __u8 direction,
                                    __u8 flags, __u32 octets) {
    if (!firewall_enabled)
        return -1;
    if (permit_all_icmp && ((key->family == 4 && key->protocol == 1) ||
                           (key->family == 6 && key->protocol == 58)))
        return -1;
    __u64 now = bpf_ktime_get_ns();
    if (established(key, direction, flags, now))
        return -1;
    struct rule_context context = {.key = *key, .direction = direction};
    __u32 slot = 0;
    // Snapshot one immutable table for the entire packet, including callback iterations.
    context.table = bpf_map_lookup_elem(&rules, &slot);
    if (!context.table)
        return deny(key, direction, 0, 5, octets);
    bpf_loop(256, find_rule, &context, 0);
    if (context.matched) {
        if (!context.action)
            return deny(key, direction, context.matched, 1, octets);
        if (remember(key, direction, flags, now))
            return deny(key, direction, context.matched, 4, octets);
        return -1;
    }
    return deny(key, direction, 0, 0, octets);
}

static long expire_connection(void *map, const void *key, void *value, void *context) {
    struct state_value *state = value;
    const struct flow_key *flow = key;
    __u64 now = *(__u64 *)context;
    int expired = 0;
    bpf_spin_lock(&state->lock);
    __u64 timeout = flow->protocol == 17 || state->stage == 4 ? 30000000000ULL : 300000000000ULL;
    if (!state->stage || state->stage == 5 || now - state->last > timeout) {
        // Claim the entry before deletion; packet handlers cannot refresh it.
        state->stage = 5;
        expired = 1;
    }
    bpf_spin_unlock(&state->lock);
    if (expired)
        bpf_map_delete_elem(map, key);
    return 0;
}

SEC("classifier")
int expire_states(struct __sk_buff *skb) {
    __u64 now = bpf_ktime_get_ns();
    bpf_for_each_map_elem(&connections, expire_connection, &now, 0);
    return 0;
}
