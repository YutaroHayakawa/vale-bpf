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

#if defined(linux)

#include <linux/kernel.h>
#include <linux/cpumask.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/types.h>
#include <bsd_glue.h>

#elif defined(__FreeBSD__)

#include <sys/param.h>
#include <sys/module.h>
#include <sys/types.h>
#include <sys/cdefs.h>
#include <sys/kernel.h>
#include <sys/conf.h>
#include <sys/malloc.h>
#include <sys/socket.h>
#include <sys/selinfo.h>
#include <sys/elf.h>
#include <net/if.h>
#include <net/if_var.h>
#include <machine/bus.h>

#else

#error Unsupported platform

#endif

#include <net/netmap.h>
#include <dev/netmap/netmap_kern.h> /* XXX Provide path in Makefile */

#include <vale_bpf.h>
#include <vale_bpf_int.h>
#include <vale_bpf_kern.h>

#define MAX_VM_ENT 256
static struct vale_bpf_vm *vm_ent[MAX_VM_ENT];

static int16_t classify(struct nm_bdg_fwd *ft, uint8_t *hint,
                 struct netmap_vp_adapter *vpna) {
  return 0;
}

static u_int vale_bpf_lookup(struct nm_bdg_fwd *ft, uint8_t *hint,
                             struct netmap_vp_adapter *vpna) {
  uint64_t ret = NM_BDG_NOPORT;

  int16_t id = classify(ft, hint, vpna);
  if (id < 0) {
    RD(1, "Classify failed");
    return NM_BDG_NOPORT;
  }

  struct vale_bpf_vm *vm = vm_ent[id];
  if (vm == NULL) {
    RD(1, "No instance that has %d", id);
    return NM_BDG_NOPORT;
  }

  if (vm->jitted) {
    ret = vm->jitted(ft->ft_buf, ft->ft_len, netmap_bdg_idx(vpna));
  } else {
    ret = vale_bpf_exec(vm, ft->ft_buf, ft->ft_len, netmap_bdg_idx(vpna));
  }

  if (ret == (uint64_t)-1) {
    RD(1, "vale_bpf_exec failed");
    return NM_BDG_NOPORT;
  }

  if (ret > NM_BDG_NOPORT) {
    RD(1, "Invalid port number %llu", ret);
    return NM_BDG_NOPORT;
  }

  RD(1, "dst: %llu", ret);

  return (u_int)ret;
}

static int vale_bpf_load_prog(uint8_t id, void *code, size_t code_len, int jit) {
  int ret;
  bool elf = code_len >= SELFMAG && !memcmp(code, ELFMAG, SELFMAG);
  struct vale_bpf_vm *tmpvm = NULL;
  struct vale_bpf_vm *newvm = NULL;

  if (code == NULL) {
    D("code is NULL");
    return -1;
  }

  struct vale_bpf_vm **vm = &vm_ent[id];
  if (*vm == NULL) {
    D("VM that has ID %u doesn't exist", id);
    return -1;
  }

  void *tmp = vale_bpf_os_malloc(code_len);
  if (tmp == NULL) {
    return -1;
  }

  size_t err = copyin(code, tmp, code_len);
  if (err != 0) {
    vale_bpf_os_free(tmp);
    return -1;
  }

  newvm = vale_bpf_create();
  if (newvm == NULL) {
    vale_bpf_os_free(tmp);
    return -1;
  }

  if (elf) {
    ret = vale_bpf_load_elf(newvm, tmp, code_len);
    if (ret < 0) {
      vale_bpf_os_free(tmp);
      return -1;
    }
  } else {
    ret = vale_bpf_load(newvm, tmp, code_len);
    if (ret < 0) {
      vale_bpf_os_free(tmp);
      return -1;
    }
  }

  if (jit) {
    vale_bpf_jit_fn fn = vale_bpf_compile(newvm);
    if (fn == NULL) {
      D("Failed to compile");
      vale_bpf_destroy(newvm);
      vale_bpf_os_free(tmp);
      return -1;
    }
    D("JIT Done");
  }

  /* swap vm instance */
  tmpvm = *vm;
  *vm = newvm;

  /* Cleanup old vm and temporary code */
  vale_bpf_destroy(tmpvm);
  vale_bpf_os_free(tmp);

  D("Successfully loaded ebpf program, Mode: %s", jit ? "JIT" : "Interpreter");

  return 0;
}

static void vale_bpf_register_vm(uint8_t id) {
  if (vm_ent[id] != NULL) {
    D("ID %u is already used", id);
    return;
  }

  vm_ent[id] = vale_bpf_create();
  D("Registered VM! ID: %u", id);
}

static void _vale_bpf_unregister_vm(uint8_t id) {
  vale_bpf_destroy(vm_ent[id]);
  vm_ent[id] = NULL;
  D("Unregistered VM! ID: %u", id);
}

static void vale_bpf_unregister_vm(uint8_t id) {
  if (vm_ent[id] == NULL) {
    D("ID %u is not used", id);
    return;
  }
  _vale_bpf_unregister_vm(id);
}

static int vale_bpf_config(struct nm_ifreq *req) {
  struct vale_bpf_req *r = (struct vale_bpf_req *)req->data;

  switch (r->method) {
    case REGISTER_VM:
      vale_bpf_register_vm(r->reg_data.id);
      break;
    case LOAD_PROG:
      return vale_bpf_load_prog(r->prog_data.id, r->prog_data.code,
          r->prog_data.code_len, r->prog_data.jit);
    case UNREGISTER_VM:
      vale_bpf_unregister_vm(r->reg_data.id);
      break;
    default:
      return -1;
  }

  return 0;
}

static struct netmap_bdg_ops vale_bpf_ops = {vale_bpf_lookup, vale_bpf_config,
                                             NULL};

static int vale_bpf_init(void) {
  struct nmreq nmr;

  /* initialize vm */
  for (int i = 0; i < MAX_VM_ENT; i++) {
    vm_ent[i] = NULL;
  }

  bzero(&nmr, sizeof(nmr));
  nmr.nr_version = NETMAP_API;
  strlcpy(nmr.nr_name, VALE_NAME, sizeof(nmr.nr_name));
  strlcat(nmr.nr_name, ":", sizeof(nmr.nr_name));
  nmr.nr_cmd = NETMAP_BDG_REGOPS;
  if (netmap_bdg_ctl(&nmr, &vale_bpf_ops)) {
    D("create a bridge named %s beforehand using vale-ctl", nmr.nr_name);
    return -ENOENT;
  }

  D("Loaded vale-bpf-" VALE_NAME);

  return 0;
}

static void vale_bpf_fini(void) {
  struct nmreq nmr;
  int error;
  struct netmap_bdg_ops tmp = {netmap_bdg_learning, NULL, NULL};

  for (int i = 0; i < MAX_VM_ENT; i++) {
    if (vm_ent[i] == NULL) {
      continue;
    }
    _vale_bpf_unregister_vm(i);
  }

  bzero(&nmr, sizeof(nmr));
  nmr.nr_version = NETMAP_API;
  strlcpy(nmr.nr_name, VALE_NAME, sizeof(nmr.nr_name));
  strlcat(nmr.nr_name, ":", sizeof(nmr.nr_name));
  nmr.nr_cmd = NETMAP_BDG_REGOPS;
  error = netmap_bdg_ctl(&nmr, &tmp);

  if (error) {
    D("failed to release VALE bridge %d", error);
  }

  D("Unloaded vale-bpf-" VALE_NAME);
}

#if defined(linux)

module_init(vale_bpf_init);
module_exit(vale_bpf_fini);
MODULE_AUTHOR("Yutaro Hayakawa");
MODULE_DESCRIPTION("VALE BPF Module");
MODULE_LICENSE("Apache2");

#elif defined(__FreeBSD__)

static int
vale_bpf_loader(module_t mod, int type, void *data)
{
  int error = 0;

  switch (type) {
  case MOD_LOAD:
    error = vale_bpf_init();
    D("Loaded vale-bpf-" VALE_NAME);
    break;
  case MOD_UNLOAD:
    vale_bpf_fini();
    D("Unloaded vale-bpf-" VALE_NAME);
    break;
  default:
    error = EINVAL;
  }
  return error;
}

DEV_MODULE(vale_bpf, vale_bpf_loader, NULL);

#else
#error Unsupported platform
#endif

