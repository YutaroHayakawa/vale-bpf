/*
 * Copyright 2017 Yutaro Hayakawa
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/rwlock.h>
#include <linux/smp.h>
#include <linux/string.h>
#include <linux/types.h>
#include <uapi/linux/if_ether.h> /* struct ethhdr */
#include <uapi/linux/in.h>       /* IPPRTO_TCP */
#include <uapi/linux/ip.h>       /* struct iphdr */
#include <uapi/linux/tcp.h>      /* struct tcphdr */

#include <bsd_glue.h> /* from netmap-release */
#include <net/netmap.h>
#include <dev/netmap/netmap_kern.h> /* XXX Provide path in Makefile */

#include <vale_bpf.h>
#include <vale_bpf_int.h>
#include <vale_bpf_kern.h>

static struct vale_bpf_vm *vm;
static rwlock_t vmlock;

static u_int vale_bpf_lookup(struct nm_bdg_fwd *ft, uint8_t *hint,
                             struct netmap_vp_adapter *vpna) {
  uint64_t ret = NM_BDG_NOPORT;

  read_lock(&vmlock);

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

  RD(1, "%llu", ret);

  return (u_int)ret;
}

static int vale_bpf_load_prog(void *code, size_t code_len) {
  int ret;
  bool elf = code_len >= SELFMAG && !memcmp(code, ELFMAG, SELFMAG);
  struct vale_bpf_vm *tmpvm = NULL;
  struct vale_bpf_vm *newvm = NULL;

  if (code == NULL) {
    D("code is NULL");
    return -EINVAL;
  }

  void *tmp = kmalloc(code_len, GFP_KERNEL);
  if (tmp == NULL) {
    return -ENOMEM;
  }

  size_t err = copy_from_user(tmp, code, code_len);
  if (err != 0) {
    kfree(tmp);
    return err;
  }

  if (vm->insts) {
    D("Program already loaded, recreating vm");
    newvm = vale_bpf_create();
    if (newvm == NULL) {
      goto error;
    }
  }

  if (elf) {
    ret = vale_bpf_load_elf(newvm, tmp, code_len);
    if (ret < 0) {
      goto error;
    }
  } else {
    ret = vale_bpf_load(newvm, tmp, code_len);
    if (ret < 0) {
      goto error;
    }
  }

  write_lock(&vmlock);

  /* swap vm instance */
  tmpvm = vm;
  vm = newvm;

  write_unlock(&vmlock);

  /* Cleanup old vm and temporary code */
  vale_bpf_destroy(tmpvm);
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

static struct netmap_bdg_ops vale_bpf_ops = {vale_bpf_lookup, vale_bpf_config,
                                             NULL};

static int vale_bpf_init(void) {
  struct nmreq nmr;

  /* initialize vm */
  vm = vale_bpf_create();
  if (vm == NULL) {
    return -ENOMEM;
  }

  rwlock_init(&vmlock);  // initialize rwlock for vm

  bzero(&nmr, sizeof(nmr));
  nmr.nr_version = NETMAP_API;
  strlcpy(nmr.nr_name, VALE_NAME, sizeof(nmr.nr_name));
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
  strlcpy(nmr.nr_name, VALE_NAME, sizeof(nmr.nr_name));
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
