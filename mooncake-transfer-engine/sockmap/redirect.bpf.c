// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct socket_table {
    __uint(type, BPF_MAP_TYPE_SOCKMAP);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, __u64);
};

struct socket_table client_socks SEC(".maps");
struct socket_table server_socks SEC(".maps");

struct counters {
    __u64 bytes;
    __u64 drops;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, struct counters);
} counts SEC(".maps");

static __always_inline int account(__u32 side, __u32 size, int verdict) {
    struct counters *c = bpf_map_lookup_elem(&counts, &side);
    if (c) {
        if (verdict == SK_PASS)
            c->bytes += size;
        else
            c->drops++;
    }
    return verdict;
}

SEC("sk_msg")
int from_client(struct sk_msg_md *msg) {
    __u32 size = msg->size;
    int verdict = bpf_msg_redirect_map(msg, &server_socks, msg->local_port,
                                       BPF_F_INGRESS);
    return account(0, size, verdict);
}

SEC("sk_msg")
int from_server(struct sk_msg_md *msg) {
    __u32 size = msg->size;
    int verdict = bpf_msg_redirect_map(
        msg, &client_socks, bpf_ntohl(msg->remote_port), BPF_F_INGRESS);
    return account(1, size, verdict);
}

char sockmap_license[] SEC("license") = "GPL";
