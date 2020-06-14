#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

const volatile struct {
  int x;
} cfg = {};

int i;

SEC("uprobe/my_probe")
int my_probe() {
  return 0;
}

SEC("perf_event")
int bpf_timer(struct bpf_perf_event_data *ctx) {
  bpf_printk("xxx %d %d\n", cfg.x, i);
  i++;
  return 0;
}

