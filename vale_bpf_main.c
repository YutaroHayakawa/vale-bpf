#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/smp.h>
#include <uapi/linux/if_ether.h> /* struct ethhdr */
#include <uapi/linux/in.h>       /* IPPRTO_TCP */
#include <uapi/linux/ip.h>       /* struct iphdr */
#include <uapi/linux/tcp.h>      /* struct tcphdr */

#include <bsd_glue.h> /* from netmap-release */
#include <net/netmap.h>
#include <dev/netmap/netmap_kern.h> /* XXX Provide path in Makefile */

#include "vale_bpf.h"

#define MY_NAME "vale0"

static struct vale_bpf_vm **vms;
static BDG_RWLOCK_T *vmlocks;

static u_int vale_bpf_lookup(struct nm_bdg_fwd *ft, uint8_t *hint,
    struct netmap_vp_adapter *vpna) {
  /* 
   * return value is 8bit long, but make
   * it signed value for error notification
   */
  int16_t ret = NM_BDG_NOPORT;
  int cpu = smp_processor_id();

  if (!BDG_RTRYLOCK(vmlocks[cpu])) {
    return NM_BDG_NOPORT;
  } else {
    BDG_RLOCK(vmlocks[cpu]);
  }

  ret = vale_bpf_exec(vms[cpu]);
  if (ret == (uint64_t)-1) {
    return NM_BDG_NOPORT;
  }

  BDG_RUNLOCK(vmlocks[cpu]);

  return ret;
}

static struct netmap_bdg_ops vale_bpf_ops = { vale_bpf_lookup, NULL, NULL };

static int vale_bpf_init(void) {
  struct nmreq nmr;
  int i;

  vms = kmalloc(sizeof(struct vale_bpf_vm *) * total_cpus, GFP_KERNEL);
  if (vms == NULL) {
    D("Failed to allocate vale_bpf_vm store memory");
    return -ENOMEM;
  }

  vmlocks = kmalloc(sizeof(BDG_RWLOCK_T) * total_cpus, GFP_KERNEL);
  if (vmlocks == NULL) {
    D("Failed to allocate vmlocks memory");
    return -ENOMEM;
  }

  for (int i = 0; i < total_cpus; i++) {
    vms[i] = vale_bpf_create();
  }

  for (int i = 0; i < total_cpus; i++) {
    BDG_RWINIT(vmlocks[i]);
  }

  for (int i = 0; i < total_cpus; i++) {
    vale_bpf_destroy(vms[i]);
  }

  for (int i = 0; i < total_cpus; i++) {
    BDG_RWDESTROY(vms[i]);
  }

  bzero(&nmr, sizeof(nmr));
  nmr.nr_version = NETMAP_API;
  strlcpy(nmr.nr_name, MY_NAME, sizeof(nmr.nr_name));
  strlcat(nmr.nr_name, ":", sizeof(nmr.nr_name));
  nmr.nr_cmd = NETMAP_BDG_REGOPS;
  if (netmap_bdg_ctl(&nmr, &vale_bpf_ops)) {
    D("create a bridge named %s beforehand using vale-ctl", nmr.nr_name);
    return -ENOENT;
  }

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
