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

static __always_inline int process(struct __sk_buff *skb, __u8 direction) {
    int sampled = 1;
    struct flow_key key = {};
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
        if (be16(ip + 6) & 0x3fff)
            goto excluded;
        transport = offset + ihl;
    } else {
        __u8 ip[40];
        if (bpf_skb_load_bytes(skb, offset, ip, 40))
            goto malformed;
        if ((ip[0] >> 4) != 6)
            goto malformed;
        octets = 40 + be16(ip + 4);
        // IPv6 jumbograms need the Hop-by-Hop Jumbo Payload option.
        if ((octets == 40 && skb->len > offset + 40) || offset + octets > skb->len)
            goto malformed;
        key.family = 6;
        key.protocol = ip[6];
        key.tos = ((ip[0] & 15) << 4) | (ip[1] >> 4);
        __builtin_memcpy(key.source, ip + 8, 16);
        __builtin_memcpy(key.destination, ip + 24, 16);
        transport = offset + 40;
#pragma unroll
        for (int i = 0; i < 8; i++) {
            if (key.protocol == 0 || key.protocol == 43 ||
                key.protocol == 60 || key.protocol == 51 || key.protocol == 44) {
                __u8 extension[8];
                if (transport + 8 > offset + octets ||
                    bpf_skb_load_bytes(skb, transport, extension, 8))
                    goto malformed;
                __u32 length = (extension[1] + 1) * 8;
                if (key.protocol == 51)
                    length = (extension[1] + 2) * 4;
                if (key.protocol == 44) {
                    goto excluded;
                }
                key.protocol = extension[0];
                transport += length;
            }
        }
        if (key.protocol == 0 || key.protocol == 43 || key.protocol == 60 ||
            key.protocol == 51 || key.protocol == 44 || transport > offset + octets)
            goto malformed;
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
    } else if ((key.family == 4 && key.protocol == 1) ||
               (key.family == 6 && key.protocol == 58)) {
        __u8 icmp[2];
        if (transport + 8 > offset + octets ||
            bpf_skb_load_bytes(skb, transport, icmp, 2))
            goto malformed;
        key.destination_port = be16(icmp);
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
    return firewall(&key, direction, tcp_flags, octets);
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
