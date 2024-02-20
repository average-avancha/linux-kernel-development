#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include "bpf/bpf_helpers.h"

struct port_rule {
  __u8 udp_action;
  __u8 tcp_action;
};

struct bpf_map_def SEC("maps") port_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(struct port_rule),
    .max_entries = 65536,
};

SEC("xdp_port_blocker")
int xdp_filter_by_port(struct xdp_md *ctx) {
  // convert the packet to a series of netowkr headers
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;

  // Check if the packet is large enough for Ethernet + IP + TCP headers
  struct ethhdr *eth = data;
  struct iphdr *ip = data + sizeof(*eth);
  struct tcphdr *tcp = (void *)ip + sizeof(*ip);
  if ((void *)tcp + sizeof(*tcp) > data_end) {
    return XDP_PASS;
  }

  // filter UDP packets
  if (ip->protocol == IPPROTO_UDP) {
    return XDP_PASS;
  }

  // You may need to get the filter rules from the map

  // Check the destination port
  if (tcp->dest == htons(11211)) {
    bpf_printk("found packet to port 11211\n");
  }

  if (tcp->dest == htons(11211) || tcp->source == htons(11211)) {
    return XDP_DROP;  // Drop packets destined to port
  }

  // Add more rules here...

  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
