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
const volatile __u32 enforcement_hooks = 3;
const volatile __u32 permit_all_icmp = 1;

struct firewall_table {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 257);
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
    __u32 generation, padding;
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
    __u8 padding[2];
    __u32 generation;
};

struct fragment_key {
    __u8 source[16], destination[16];
    __u32 id, ifindex, vlan[2];
    __u8 family, protocol, direction, padding;
};

struct fragment_packet {
    __u32 start, length, limit, expected;
    __u8 more;
};

#define FRAGMENT_TIMEOUT 30000000000ULL
#define FRAGMENT_RANGES 64

struct fragment_value {
    struct bpf_spin_lock lock;
    __u32 generation;
    __u64 created;
    __u32 rule, bytes, end, limit;
    __u16 source_port, destination_port;
    __u8 protocol, status;
    __u16 count;
    struct {
        __u16 start, end;
    } ranges[FRAGMENT_RANGES];
};

// Pending, authorized, invalid/completed, and retiring entries are never evicted.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct fragment_key);
    __type(value, struct fragment_value);
} fragments SEC(".maps");

// Per-CPU parsing scratch and a raw seed keep fragment data off the BPF stack.
struct fragment_seed {
    struct fragment_key key;
    struct fragment_packet packet;
    __u8 bytes[sizeof(struct fragment_value)] __attribute__((aligned(8)));
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct fragment_seed);
} fragment_seeds SEC(".maps");

struct firewall_decision {
    __u32 generation, rule;
    __u8 allowed;
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

static __always_inline int deny(struct flow_key *key, __u8 direction,
                                __u32 rule, __u8 reason, __u32 octets, __u32 generation) {
    struct drop_event *event = bpf_ringbuf_reserve(&drops, sizeof(*event), 0);
    if (event) {
        event->key = *key;
        event->time = bpf_ktime_get_ns();
        event->rule = rule;
        event->octets = octets;
        event->direction = direction;
        event->generation = generation;
        event->reason = reason;
        __builtin_memset(event->padding, 0, sizeof(event->padding));
        bpf_ringbuf_submit(event, 0);
    } else {
        __u32 index = 0;
        __u64 *count = bpf_map_lookup_elem(&drop_losses, &index);
        if (count)
            *count += 1;
    }
    // Both hooks still evaluate policy; only selected hooks return TCX_DROP.
    return audit_mode || !(enforcement_hooks & direction) ? -1 : 2;
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
                                       __u8 flags, __u64 now, __u32 generation) {
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
    if (state->generation != generation) {
        // An old in-flight packet must not invalidate state from a newer table.
    } else if (!state->stage || state->stage == 5 || now - state->last > timeout) {
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
                                    __u8 flags, __u64 now, __u32 generation) {
    if (key->protocol != 17 && !(key->protocol == 6 && (flags & 0x17) == 2))
        return 0;
    struct flow_key lookup;
    state_key(&lookup, key, direction, 0);
    struct state_value value = {.stage = 1, .last = now, .generation = generation};
    long result = bpf_map_update_elem(&connections, &lookup, &value, BPF_NOEXIST);
    if (result == -17) {
        struct state_value *existing = bpf_map_lookup_elem(&connections, &lookup);
        if (!existing)
            return 1;
        int retiring = 0;
        bpf_spin_lock(&existing->lock);
        if (existing->stage == 5 || existing->generation > generation) {
            retiring = 1;
        } else {
            if (existing->generation != generation || !existing->stage || existing->stage >= 3)
                existing->stage = 1;
            existing->last = now;
            existing->generation = generation;
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
                                    __u8 flags, __u32 octets,
                                    struct firewall_decision *decision) {
    if (!firewall_enabled)
        return -1;
    __u64 now = bpf_ktime_get_ns();
    struct rule_context context = {.key = *key, .direction = direction};
    __u32 slot = 0;
    // Snapshot one immutable table for the entire packet, including callback iterations.
    context.table = bpf_map_lookup_elem(&rules, &slot);
    if (!context.table)
        return deny(key, direction, 0, 5, octets, 0);
    __u32 metadata = 256;
    struct firewall_rule *version = bpf_map_lookup_elem(context.table, &metadata);
    if (!version)
        return deny(key, direction, 0, 5, octets, 0);
    __u32 generation = version->id;
    decision->generation = generation;
    if ((permit_all_icmp && ((key->family == 4 && key->protocol == 1) ||
                            (key->family == 6 && key->protocol == 58))) ||
        established(key, direction, flags, now, generation)) {
        decision->allowed = 1;
        return -1;
    }
    bpf_loop(256, find_rule, &context, 0);
    if (context.matched) {
        if (!context.action)
            return deny(key, direction, context.matched, 1, octets, generation);
        if (remember(key, direction, flags, now, generation))
            return deny(key, direction, context.matched, 4, octets, generation);
        decision->rule = context.matched;
        decision->allowed = 1;
        return -1;
    }
    return deny(key, direction, 0, 0, octets, generation);
}

static __noinline int reserve_fragment(struct fragment_key *key,
                                       struct fragment_packet *packet) {
    __u32 slot = 0, metadata = 256;
    void *table = bpf_map_lookup_elem(&rules, &slot);
    if (!table)
        return 5;
    struct firewall_rule *version = bpf_map_lookup_elem(table, &metadata);
    if (!version)
        return 5;
    struct fragment_seed *seed = bpf_map_lookup_elem(&fragment_seeds, &slot);
    if (!seed)
        return 8;
    __builtin_memset(seed->bytes, 0, sizeof(seed->bytes));
    struct fragment_value *initial = (void *)seed->bytes;
    initial->generation = version->id;
    initial->created = bpf_ktime_get_ns();
    initial->bytes = packet->length;
    initial->status = 1;
    initial->count = 1;
    initial->end = packet->expected;
    initial->limit = packet->limit;
    initial->ranges[0].end = packet->length;
    long result = bpf_map_update_elem(&fragments, key, initial, BPF_NOEXIST);
    if (!result)
        return 0;
    if (result != -17)
        return 8;
    struct fragment_value *value = bpf_map_lookup_elem(&fragments, key);
    if (value) {
        bpf_spin_lock(&value->lock);
        if (value->status != 4)
            value->status = 3;
        bpf_spin_unlock(&value->lock);
    }
    return 7;
}

static __noinline int authorize_fragment(struct fragment_key *fragment,
                                         struct flow_key *key,
                                         struct firewall_decision *decision,
                                         __u32 octets, int result) {
    struct fragment_value *value = bpf_map_lookup_elem(&fragments, fragment);
    int authorized = 0;
    if (value) {
        bpf_spin_lock(&value->lock);
        if (value->status == 1 && value->generation == decision->generation &&
            decision->allowed) {
            value->source_port = key->source_port;
            value->destination_port = key->destination_port;
            value->protocol = key->protocol;
            value->rule = decision->rule;
            value->status = 2;
            authorized = 1;
        } else if (value->status != 4) {
            value->status = 3;
        }
        bpf_spin_unlock(&value->lock);
    }
    if (!decision->allowed)
        return result;
    if (!authorized)
        return deny(key, fragment->direction, decision->rule, 7, octets, decision->generation);
    return -1;
}

static __noinline int follow_fragment(struct fragment_key *fragment,
                                      struct fragment_packet *packet,
                                      struct flow_key *key, __u32 octets) {
    __u32 slot = 0, metadata = 256;
    void *table = bpf_map_lookup_elem(&rules, &slot);
    if (!table)
        return deny(key, fragment->direction, 0, 5, octets, 0);
    struct firewall_rule *version = bpf_map_lookup_elem(table, &metadata);
    if (!version)
        return deny(key, fragment->direction, 0, 5, octets, 0);
    __u32 generation = version->id, rule = 0;
    __u8 reason = 6;
    __u64 now = bpf_ktime_get_ns();
    struct fragment_value *value = bpf_map_lookup_elem(&fragments, fragment);
    if (!value)
        return deny(key, fragment->direction, 0, reason, octets, generation);
    __u32 end = packet->start + packet->length;
    int allowed = 0;
    bpf_spin_lock(&value->lock);
    if (value->generation == generation && now - value->created <= FRAGMENT_TIMEOUT &&
        value->status == 2) {
        key->source_port = value->source_port;
        key->destination_port = value->destination_port;
        key->protocol = value->protocol;
        rule = value->rule;
        int invalid = end > value->limit || value->count >= FRAGMENT_RANGES ||
                      (value->end && (end > value->end ||
                       (packet->more && end >= value->end) ||
                       (!packet->more && end != value->end)));
#pragma unroll
        for (int i = 0; i < FRAGMENT_RANGES; i++) {
            if (i < value->count && packet->start < value->ranges[i].end &&
                end > value->ranges[i].start)
                invalid = 1;
            if (!packet->more && i < value->count && value->ranges[i].end > end)
                invalid = 1;
        }
        if (invalid) {
            value->status = 3;
            reason = 7;
        } else {
            __u32 index = value->count;
            if (index < FRAGMENT_RANGES) {
                value->ranges[index].start = packet->start;
                value->ranges[index].end = end;
                value->count++;
                value->bytes += packet->length;
                if (!packet->more)
                    value->end = end;
                if (value->end && value->bytes == value->end)
                    value->status = 3;
                allowed = 1;
            }
        }
    }
    bpf_spin_unlock(&value->lock);
    if (!allowed)
        return deny(key, fragment->direction, rule, reason, octets, generation);
    return -1;
}

struct expiry_context {
    __u64 now;
    __u32 generation;
};

static long expire_connection(void *map, const void *key, void *value, void *context) {
    struct state_value *state = value;
    const struct flow_key *flow = key;
    struct expiry_context *expiry = context;
    int expired = 0;
    bpf_spin_lock(&state->lock);
    __u64 timeout = flow->protocol == 17 || state->stage == 4 ? 30000000000ULL : 300000000000ULL;
    if (state->generation != expiry->generation || !state->stage || state->stage == 5 || expiry->now - state->last > timeout) {
        // Claim the entry before deletion; packet handlers cannot refresh it.
        state->stage = 5;
        expired = 1;
    }
    bpf_spin_unlock(&state->lock);
    if (expired)
        bpf_map_delete_elem(map, key);
    return 0;
}

static long expire_fragment(void *map, const void *key, void *value, void *context) {
    struct fragment_value *fragment = value;
    struct expiry_context *expiry = context;
    int expired = 0;
    bpf_spin_lock(&fragment->lock);
    if (fragment->generation != expiry->generation ||
        expiry->now - fragment->created > FRAGMENT_TIMEOUT || fragment->status == 4) {
        fragment->status = 4;
        expired = 1;
    }
    bpf_spin_unlock(&fragment->lock);
    if (expired)
        bpf_map_delete_elem(map, key);
    return 0;
}

SEC("classifier")
int expire_states(struct __sk_buff *skb) {
    __u32 slot = 0, metadata = 256;
    void *table = bpf_map_lookup_elem(&rules, &slot);
    if (!table)
        return 0;
    struct firewall_rule *version = bpf_map_lookup_elem(table, &metadata);
    if (!version)
        return 0;
    struct expiry_context expiry = {.now = bpf_ktime_get_ns(), .generation = version->id};
    bpf_for_each_map_elem(&connections, expire_connection, &expiry, 0);
    bpf_for_each_map_elem(&fragments, expire_fragment, &expiry, 0);
    return 0;
}
