#include <linux/bpf.h>
#include <bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
	__uint(max_entries, 64); // max queue size 64
} xdev_map SEC(".maps");

SEC("xdp")
int xdev_hook (struct xdp_md *ctx)
{
	int q_index = ctx->rx_queue_index;

	if (bpf_map_lookup_elem(&xdev_map, &q_index))
		return bpf_redirect_map(&xdev_map, q_index, 0);

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
