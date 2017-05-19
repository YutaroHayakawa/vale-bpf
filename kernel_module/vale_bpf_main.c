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
#include <linux/rwlock.h>

#include <bsd_glue.h> /* from netmap-release */
#include <net/netmap.h>
#include <dev/netmap/netmap_kern.h> /* XXX Provide path in Makefile */

#include "vale_bpf_kern.h"
#include "vale_bpf_int.h"
#include "../include/vale_bpf.h"

#define MY_NAME "vale0"

static struct vale_bpf_vm *vm;
static rwlock_t vmlock;

static u_int vale_bpf_lookup(struct nm_bdg_fwd *ft, uint8_t *hint,
    struct netmap_vp_adapter *vpna) {
  uint64_t ret = NM_BDG_NOPORT;

  if (!read_trylock(&vmlock)) {
    return NM_BDG_NOPORT;
  } else {
    read_lock(&vmlock);
  }

  ret = vale_bpf_exec(vm, ft->ft_buf, ft->ft_len);
  if (ret == (uint64_t)-1) {
    read_unlock(&vmlock);
    RD(1, "vale_bpf_exec failed");
    return NM_BDG_NOPORT;
  }

  if (ret > NM_BDG_NOPORT) {
    read_unlock(&vmlock);
    return NM_BDG_NOPORT;
  }

  read_unlock(&vmlock);

  return (u_int)ret;
}

static int vale_bpf_load_prog(void *code, unsigned long code_len) {
  int ret;
  bool elf = code_len >= SELFMAG && !memcmp(code, ELFMAG, SELFMAG);

  if (code == NULL) {
    D("code is NULL");
    return -EINVAL;
  }

  void *tmp = kmalloc(code_len, GFP_KERNEL);
  if (tmp == NULL) {
    return -ENOMEM;
  }

  unsigned long err = copy_from_user(tmp, code, code_len);
  if (err != 0) {
    kfree(tmp);
    return err;
  }

  write_lock(&vmlock);

  if (vm->insts) {
    D("Program already loaded, recreating vm");
    vale_bpf_destroy(vm);
    vm = vale_bpf_create();
    if (vm == NULL) {
      goto error;
    }
  }

  if (elf) {
    ret = vale_bpf_load_elf(vm, tmp, code_len, NULL);
    if (ret < 0) {
      goto error;
    }
  } else {
    ret = vale_bpf_load(vm, tmp, code_len, NULL);
    if (ret < 0) {
      goto error;
    }
  }

  write_unlock(&vmlock);
  kfree(tmp);

  D("Successfully loaded ebpf program");

  return 0;

error:
  write_unlock(&vmlock);
  kfree(tmp);

  D("Failed to load ebpf program");

  return -1;
}

static int vale_bpf_config(struct nm_ifreq *req) {
  int ret;
  struct vale_bpf_req *r = (struct vale_bpf_req *)req->data;

  switch (r->method) {
    case LOAD_PROG:
      ret = vale_bpf_load_prog(r->data, r->len);
      break;
    default:
      ret = -1;
      break;
  }
  return ret;
}

static struct netmap_bdg_ops vale_bpf_ops = { vale_bpf_lookup, vale_bpf_config, NULL };

static int vale_bpf_init(void) {
  struct nmreq nmr;

  /* initialize vm */
  vm = vale_bpf_create();
  if (vm == NULL) {
    return -ENOMEM;
  }

  rwlock_init(&vmlock); // initialize rwlock for vm

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
  int error;
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

  D("Unloaded vale-bpf");

  vale_bpf_destroy(vm);
}

module_init(vale_bpf_init);
module_exit(vale_bpf_fini);
MODULE_AUTHOR("Yutaro Hayakawa");
MODULE_DESCRIPTION("VALE BPF Module");
MODULE_LICENSE("Dual BSD/GPL");
