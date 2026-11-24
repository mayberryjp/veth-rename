// SPDX-License-Identifier: MIT
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct flow_key {
    __u8 source[16];
    __u8 destination[16];
    __u16 source_port;
    __u16 destination_port;
    __u8 protocol;
    __u8 family;
    __u8 tos;
    __u8 padding;
};

#include "firewall.h"

struct packet_event {
    struct flow_key key;
    __u32 octets;
    __u8 flags;
    __u8 padding[3];
    __u64 time;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4194304);
} packets SEC(".maps");

const volatile __u32 sampling_rate = 1;
const volatile __u32 capture_filter = 0;
const volatile struct flow_key collector = {};

// Both hooks share one atomic sequence; sampling precedes parsing.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} sample_sequence SEC(".maps");

// Ring-buffer losses, malformed IP, fragments, filtered packets, collector traffic.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 5);
    __type(key, __u32);
    __type(value, __u64);
} losses SEC(".maps");

static __always_inline void loss(__u32 index) {
    __u64 *count = bpf_map_lookup_elem(&losses, &index);
    if (count)
        *count += 1;
}

static __always_inline __u16 be16(const __u8 *p) {
    return ((__u16)p[0] << 8) | p[1];
}

struct ipv6_context {
    __u32 offset, octets, transport;
};

static __noinline int parse_ipv6(struct __sk_buff *skb, struct flow_key *key,
                                 struct fragment_key *fragment,
                                 struct fragment_packet *piece,
                                 struct ipv6_context *context) {
    __u8 ip[40];
    __u32 offset = context->offset;
    if (bpf_skb_load_bytes(skb, offset, ip, 40) || (ip[0] >> 4) != 6)
        return -1;
    __u32 octets = 40 + be16(ip + 4);
    // IPv6 jumbograms need the Hop-by-Hop Jumbo Payload option.
    if ((octets == 40 && skb->len > offset + 40) || offset + octets > skb->len)
        return -1;
    key->family = 6;
    key->protocol = ip[6];
    key->tos = ((ip[0] & 15) << 4) | (ip[1] >> 4);
    __builtin_memcpy(key->source, ip + 8, 16);
    __builtin_memcpy(key->destination, ip + 24, 16);
    __u32 transport = offset + 40;
    int fragmented = 0, fragment_header = 0;
#pragma unroll
    for (int i = 0; i < 8; i++) {
        if (key->protocol == 0 || key->protocol == 43 ||
            key->protocol == 60 || key->protocol == 51 || key->protocol == 44) {
            __u8 extension[8];
            if (transport + 8 > offset + octets ||
                bpf_skb_load_bytes(skb, transport, extension, 8))
                return -1;
            __u32 length = (extension[1] + 1) * 8;
            if (key->protocol == 51)
                length = (extension[1] + 2) * 4;
            if (key->protocol == 44) {
                if (fragment_header || extension[1] || (be16(extension + 2) & 6))
                    return -1;
                fragment_header = 1;
                __u16 bits = be16(extension + 2);
                if (bits) {
                    fragmented = 1;
                    fragment->id = ((__u32)be16(extension + 4) << 16) | be16(extension + 6);
                    fragment->protocol = extension[0];
                    piece->start = bits & 0xfff8;
                    piece->more = bits & 1;
                    piece->limit = 65535 - (transport - offset - 40);
                    piece->length = offset + octets - transport - 8;
                }
                length = 8;
            }
            key->protocol = extension[0];
            transport += length;
            if (fragmented && piece->start)
                break;
        }
    }
    if (transport > offset + octets ||
        (!(fragmented && piece->start) &&
         (key->protocol == 0 || key->protocol == 43 || key->protocol == 60 ||
          key->protocol == 51 || key->protocol == 44)))
        return -1;
    context->octets = octets;
    context->transport = transport;
    return fragmented;
}

static __always_inline int process(struct __sk_buff *skb, __u8 direction) {
    int sampled = 1;
    struct flow_key key = {};
    int fragmented = 0;
    __u64 octets = 0;
    if (sampling_rate > 1) {
        __u32 index = 0;
        __u64 *sequence = bpf_map_lookup_elem(&sample_sequence, &index);
        if (!sequence) {
            if (firewall_enabled)
                goto malformed;
            return -1;
        }
        __u64 number = __sync_fetch_and_add(sequence, 1);
        if ((number + 1) % sampling_rate) {
            sampled = 0;
            if (!firewall_enabled)
                return -1;
        }
    }
    __u32 scratch_index = 0;
    struct fragment_seed *scratch = bpf_map_lookup_elem(&fragment_seeds, &scratch_index);
    if (!scratch)
        goto malformed;
    struct fragment_key *fragment = &scratch->key;
    struct fragment_packet *piece = &scratch->packet;
    __builtin_memset(fragment, 0, sizeof(*fragment));
    __builtin_memset(piece, 0, sizeof(*piece));
    fragment->ifindex = skb->ifindex;
    fragment->direction = direction;
    __u8 eth[14];
    if (bpf_skb_load_bytes(skb, 0, eth, sizeof(eth)))
        goto malformed;
    __u16 type = be16(eth + 12);
    __u32 offset = 14;
#pragma unroll
    for (int i = 0; i < 2; i++) {
        if (type == 0x8100 || type == 0x88a8) {
            __u8 vlan[4];
            if (bpf_skb_load_bytes(skb, offset, vlan, 4))
                goto malformed;
            fragment->vlan[i] = ((__u32)type << 16) | be16(vlan);
            type = be16(vlan + 2);
            offset += 4;
        }
    }
    if (type == 0x0806)
        return -1;
    if (type != 0x0800 && type != 0x86dd) {
        if (firewall_enabled)
            return deny(&key, direction, 0, 3, skb->len, 0);
        return -1;
    }
    __u32 transport = 0;
    if (type == 0x0800) {
        __u8 ip[20];
        if (bpf_skb_load_bytes(skb, offset, ip, 20))
            goto malformed;
        __u32 ihl = (ip[0] & 15) * 4;
        if ((ip[0] >> 4) != 4 || ihl < 20)
            goto malformed;
        octets = be16(ip + 2);
        if (octets < ihl || offset + octets > skb->len)
            goto malformed;
        key.family = 4;
        key.protocol = ip[9];
        key.tos = ip[1];
        __builtin_memcpy(key.source, ip + 12, 4);
        __builtin_memcpy(key.destination, ip + 16, 4);
        transport = offset + ihl;
        __u16 bits = be16(ip + 6);
        if (bits & 0x3fff) {
            if (bits & 0xc000)
                goto malformed;
            fragmented = 1;
            fragment->id = be16(ip + 4);
            fragment->protocol = key.protocol;
            piece->start = (bits & 0x1fff) * 8;
            piece->more = !!(bits & 0x2000);
            piece->length = octets - ihl;
            piece->limit = 65535 - ihl;
        }
    } else {
        struct ipv6_context context = {.offset = offset};
        fragmented = parse_ipv6(skb, &key, fragment, piece, &context);
        if (fragmented < 0)
            goto malformed;
        octets = context.octets;
        transport = context.transport;
    }
    if (fragmented) {
        if (!piece->length || piece->start + piece->length > piece->limit ||
            (piece->more && piece->length % 8))
            goto malformed;
        if (!firewall_enabled)
            goto excluded;
        fragment->family = key.family;
        __builtin_memcpy(fragment->source, key.source, 16);
        __builtin_memcpy(fragment->destination, key.destination, 16);
        if (piece->start) {
            if (sampled)
                loss(2);
            return follow_fragment(fragment, piece, &key, octets);
        }
    }
    __u8 tcp_flags = 0;
    if (key.protocol == 6 || key.protocol == 17 || key.protocol == 132) {
        __u8 ports[4];
        __u32 minimum = key.protocol == 6 ? 20 : key.protocol == 17 ? 8 : 12;
        if (transport + minimum > offset + octets ||
            bpf_skb_load_bytes(skb, transport, ports, 4))
            goto malformed;
        key.source_port = be16(ports);
        key.destination_port = be16(ports + 2);
        if (key.protocol == 6) {
            __u8 tcp_offset;
            if (bpf_skb_load_bytes(skb, transport + 12, &tcp_offset, 1))
                goto malformed;
            __u32 tcp_length = (tcp_offset >> 4) * 4;
            if (tcp_length < 20 || transport + tcp_length > offset + octets)
                goto malformed;
            if (bpf_skb_load_bytes(skb, transport + 13, &tcp_flags, 1))
                goto malformed;
        }
        if (fragmented && key.protocol == 17) {
            __u8 udp[8];
            if (bpf_skb_load_bytes(skb, transport, udp, 8))
                goto malformed;
            piece->expected = piece->length - (offset + octets - transport) + be16(udp + 4);
            if (be16(udp + 4) < 8 || piece->expected <= piece->length ||
                piece->expected > piece->limit)
                goto malformed;
        }
    } else if ((key.family == 4 && key.protocol == 1) ||
               (key.family == 6 && key.protocol == 58)) {
        __u8 icmp[2];
        if (transport + 8 > offset + octets ||
            bpf_skb_load_bytes(skb, transport, icmp, 2))
            goto malformed;
        key.destination_port = be16(icmp);
    }
    if (fragmented) {
        if (sampled)
            loss(2);
        int reason = reserve_fragment(fragment, piece);
        if (reason)
            return deny(&key, direction, 0, reason, octets, 0);
        goto enforce;
    }
    if (!sampled)
        goto enforce;
    if ((capture_filter == 1 && key.family != 4) ||
        (capture_filter == 2 && key.family != 6) ||
        (capture_filter == 3 && key.protocol != 6) ||
        (capture_filter == 4 && key.protocol != 17) ||
        (capture_filter == 5 && !(key.family == 4 && key.protocol == 1)) ||
        (capture_filter == 6 && !(key.family == 6 && key.protocol == 58))) {
        loss(3);
        goto enforce;
    }
    if (key.protocol == 17 && key.family == collector.family &&
        key.destination_port == collector.destination_port) {
        int matches = 1;
#pragma unroll
        for (int i = 0; i < 16; i++) {
            if (key.destination[i] != collector.destination[i])
                matches = 0;
        }
        if (matches) {
            loss(4);
            goto enforce;
        }
    }
    struct packet_event *event = bpf_ringbuf_reserve(&packets, sizeof(*event), 0);
    if (!event) {
        loss(0);
        goto enforce;
    }
    event->key = key;
    event->octets = octets;
    event->flags = tcp_flags;
    __builtin_memset(event->padding, 0, 3);
    event->time = bpf_ktime_get_ns();
    bpf_ringbuf_submit(event, 0);
enforce:
    {
        struct firewall_decision decision = {};
        int result = firewall(&key, direction, tcp_flags, octets, &decision);
        if (fragmented)
            return authorize_fragment(fragment, &key, &decision, octets, result);
        return result;
    }
malformed:
    if (sampled)
        loss(1);
    if (firewall_enabled)
        return deny(&key, direction, 0, 2, skb->len, 0);
    return -1;
excluded:
    if (sampled)
        loss(2);
    if (firewall_enabled)
        return deny(&key, direction, 0, 3, octets, 0);
    return -1;
}

SEC("classifier")
int meter(struct __sk_buff *skb) {
    return process(skb, 1);
}

SEC("classifier")
int meter_egress(struct __sk_buff *skb) {
    return process(skb, 2);
}

char LICENSE[] SEC("license") = "GPL";
