// go:build ignore

#include <linux/types.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, __u64);
  __uint(max_entries, 2);
} pkt_count SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, __u16);
  __uint(max_entries, 1);
} config SEC(".maps");

SEC("xdp")
int drop_tcp_packet(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;

  // Parse Ethernet header
  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end) {
    return XDP_PASS;
  }

  // Check if it's an IP packet
  if (eth->h_proto != bpf_htons(ETH_P_IP)) {
    return XDP_PASS;
  }

  // Parse IP header with bounds check
  struct iphdr *ip = (struct iphdr *)(eth + 1);
  if ((void *)(ip + 1) > data_end) {
    return XDP_PASS;
  }

  // Check if it's TCP
  if (ip->protocol != IPPROTO_TCP) {
    return XDP_PASS;
  }

  struct tcphdr *tcp = (struct tcphdr *)((__u8 *)ip + ip->ihl * 4);
  if ((void *)(tcp + 1) > data_end) {
    return XDP_PASS;
  }

  __u32 config_key = 0;
  __u16 *port_ptr = bpf_map_lookup_elem(&config, &config_key);
  __u16 drop_port = port_ptr ? bpf_htons(*port_ptr) : bpf_htons(4040);

  __u32 total_key = 0;
  __u64 *total_count = bpf_map_lookup_elem(&pkt_count, &total_key);
  if (total_count) {
    __sync_fetch_and_add(total_count, 1);
  }

  if (tcp->dest == drop_port && (tcp->syn && !tcp->ack)) {
    __u32 drop_key = 1;
    __u64 *drop_count = bpf_map_lookup_elem(&pkt_count, &drop_key);
    if (drop_count) {
      __sync_fetch_and_add(drop_count, 1);
    }
    return XDP_DROP;
  }
  return XDP_PASS;
}

char __license[] SEC("license") = "Dual MIT/GPL";
