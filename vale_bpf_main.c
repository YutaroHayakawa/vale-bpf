#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/types.h>
#include <uapi/linux/if_ether.h> /* struct ethhdr */
#include <uapi/linux/in.h>       /* IPPRTO_TCP */
#include <uapi/linux/ip.h>       /* struct iphdr */
#include <uapi/linux/tcp.h>      /* struct tcphdr */

#include <bsd_glue.h> /* from netmap-release */
#include <net/netmap.h>
#include <dev/netmap/netmap_kern.h> /* XXX Provide path in Makefile */

#include "vale_bpf.h"

#define MY_NAME "vale0"

static struct vale_bpf_vm *vm;

static u_int vale_bpf_lookup(struct nm_bdg_fwd *ft, uint8_t *hint,
    struct netmap_vp_adapter *vpna) {
  return NM_BDG_DROP;
}

static struct netmap_bdg_ops vale_bpf_ops = { vale_bpf_lookup, NULL, NULL };

static int vale_bpf_init(void) {
  struct nmreq nmr;
  int i;
  bzero(&nmr, sizeof(nmr));
  nmr.nr_version = NETMAP_API;
  strlcpy(nmr.nr_name, MY_NAME, sizeof(nmr.nr_name));
  strlcat(nmr.nr_name, ":", sizeof(nmr.nr_name));
  nmr.nr_cmd = NETMAP_BDG_REGOPS;
  if (netmap_bdg_ctl(&nmr, &vale_bpf_ops)) {
    D("create a bridge named %s beforehand using vale-ctl", nmr.nr_name);
    return -ENOENT;
  }

  vm = vale_bpf_create();
  vale_bpf_destroy(vm);

  D("Loaded vale-bpf");

  return 0;
}

static void vale_bpf_fini(void) {
  struct nmreq nmr;
  int i, error;
  struct netmap_bdg_ops tmp = {netmap_bdg_learning, NULL, NULL};

  bzero(&nmr, sizeof(nmr));
  nmr.nr_version = NETMAP_API;
  strlcpy(nmr.nr_name, MY_NAME, sizeof(nmr.nr_name));
  strlcat(nmr.nr_name, ":", sizeof(nmr.nr_name));
  nmr.nr_cmd = NETMAP_BDG_REGOPS;
  error = netmap_bdg_ctl(&nmr, &tmp);

  if (error) {
    D("failed to release VALE bridge %d", error);
  }
}

module_init(vale_bpf_init);
module_exit(vale_bpf_fini);
MODULE_AUTHOR("Yutaro Hayakawa");
MODULE_DESCRIPTION("VALE BPF Module");
MODULE_LICENSE("Dual BSD/GPL");
