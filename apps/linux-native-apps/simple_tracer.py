from vale_bpf import VALE_BPF

# simply print message when VALE got packet

b = VALE_BPF(text="""
// FIXME: define struct vale_bpf_md
struct vale_bpf_md {
    uint8_t *pkt;
    uint16_t pkt_len;
};

int simple_tracer(struct vale_bpf_md *md) {
  bpf_trace_printk("Got Packet!\\n");
  return 255;
}
""")

b.attach_vale_bpf("vale0:", "simple_tracer")

b.trace_print()
