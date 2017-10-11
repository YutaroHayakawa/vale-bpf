int test(struct vale_bpf_md *md) {
  bpf_trace_printk("test\n");
  return 255;
}
