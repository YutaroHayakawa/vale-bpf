#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>

struct hash_ent {
    uint64_t mac;
    uint64_t ports;
};

#define BUCKET_NUM    1024

#define mix(a, b, c)                                                    \
do {                                                                    \
    a -= b; a -= c; a ^= (c >> 13);                                 \
    b -= c; b -= a; b ^= (a << 8);                                  \
    c -= a; c -= b; c ^= (b >> 13);                                 \
    a -= b; a -= c; a ^= (c >> 12);                                 \
    b -= c; b -= a; b ^= (a << 16);                                 \
    c -= a; c -= b; c ^= (b >> 5);                                  \
    a -= b; a -= c; a ^= (c >> 3);                                  \
    b -= c; b -= a; b ^= (a << 10);                                 \
    c -= a; c -= b; c ^= (b >> 15);                                 \
} while (0)

static __attribute__((always_inline)) uint32_t
learning_bridge_rthash(const uint8_t *addr)
{
    uint32_t a = 0x9e3779b9, b = 0x9e3779b9, c = 0; // hask key

    b += addr[5] << 8;
    b += addr[4];
    a += addr[3] << 24;
    a += addr[2] << 16;
    a += addr[1] << 8;
    a += addr[0];

    mix(a, b, c);
    return (c & (BUCKET_NUM - 1));
}

BPF_PERCPU_ARRAY(ft, struct hash_ent , BUCKET_NUM);
BPF_PERCPU_ARRAY(last_smac_cache, uint64_t, 1);

uint32_t
xdp_l2_bridge(struct xdp_md *md)
{
  uint8_t *data = (uint8_t *)md->data;
  uint8_t *data_end = (uint8_t *)md->data_end;
  uint32_t sh, dh;
  uint64_t dst, mysrc = md->ingress_ifindex;
    struct hash_ent *ft_ent;

  if (data + 14 > data_end) {
      return XDP_DROP;
  }

  uint64_t smac, dmac;
  dmac = (*(uint64_t *)(data)) & 0xffffffffffff;
  smac = (*(uint64_t *)(data + 4));
  smac >>= 16;

  uint64_t *last_smac;
  last_smac = last_smac_cache.lookup(&(uint32_t){0});
  if (last_smac == NULL) {
        return XDP_DROP;
  }

  if (((data[6] & 1) == 0) && (*last_smac != smac)) {
        sh = learning_bridge_rthash((uint8_t *)(data + 6));

        ft_ent = ft.lookup(&sh);
        if (ft_ent == NULL) {
            return XDP_DROP;
        }

        *last_smac = ft_ent->mac = smac;
        ft_ent->ports = mysrc;
  }

  dst = XDP_DROP;
  if ((data[0] & 1) == 0) {
      dh = learning_bridge_rthash(data);
      ft_ent = ft.lookup(&dh);
      if (ft_ent && ft_ent->mac == dmac) {
      bpf_trace_printk("%p\n", ft_ent);
          dst = bpf_redirect(ft_ent->ports, 0);
      }
  }

  bpf_trace_printk("%u\n", dst);
  return dst;
}
