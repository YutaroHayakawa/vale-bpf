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

#include <sys/ebpf.h>
#include <sys/ebpf_types.h>

#include <net/vale_bpf.h>

struct vale_bpf_ctx {
  struct nm_bdg_fwd *ft;
  uint8_t *hint;
  struct netmap_vp_adapter *vpna;
};

static struct ebpf_vm *vm;
static int jit_mode;

static u_int vale_bpf_lookup(struct nm_bdg_fwd *ft, uint8_t *hint,
                             struct netmap_vp_adapter *vpna) {
  uint64_t ret = NM_BDG_NOPORT;
  struct vale_bpf_ctx ctx;

  ctx.ft = ft;
  ctx.hint = hint;
  ctx.vpna = vpna;

  if (jit_mode) {
    ret = ebpf_exec_jit(vm, &ctx, sizeof(ctx));
  } else {
    ret = ebpf_exec(vm, &ctx, sizeof(ctx));
  }

  if (ret == (uint64_t)-1) {
    ND("lookup failed");
    return NM_BDG_NOPORT;
  }

  if (ret > NM_BDG_NOPORT) {
    return NM_BDG_NOPORT;
  }

  ND("dst: %lu", ret);

  return (u_int)ret;
}

static int vale_bpf_load_prog(void *code, size_t code_len, int jit) {
  int ret;
  bool elf = code_len >= SELFMAG && !memcmp(code, ELFMAG, SELFMAG);
  struct ebpf_vm *tmpvm = NULL;
  struct ebpf_vm *newvm = NULL;

  if (code == NULL) {
    D("code is NULL");
    return -1;
  }

  void *tmp = ebpf_malloc(code_len);
  if (tmp == NULL) {
    return -1;
  }

  size_t err = copyin(code, tmp, code_len);
  if (err != 0) {
    ebpf_free(tmp);
    return -1;
  }

  newvm = ebpf_create();
  if (newvm == NULL) {
    ebpf_free(tmp);
    return -1;
  }

  if (elf) {
    ret = ebpf_load_elf(newvm, tmp, code_len);
    if (ret < 0) {
      ebpf_free(tmp);
      return -1;
    }
  } else {
    ret = ebpf_load(newvm, tmp, code_len);
    if (ret < 0) {
      ebpf_free(tmp);
      return -1;
    }
  }

  if (jit) {
    ebpf_jit_fn fn = ebpf_compile(newvm);
    if (fn == NULL) {
      D("Failed to compile");
      ebpf_destroy(newvm);
      ebpf_free(tmp);
      return -1;
    }
  }

  /* swap vm instance */
  tmpvm = vm;
  vm = newvm;

  /* set jit flag */
  jit_mode = jit;

  /* Cleanup old vm and temporary code */
  ebpf_destroy(tmpvm);
  ebpf_free(tmp);

  D("Successfully loaded ebpf program, Mode: %s", jit ? "JIT" : "Interpreter");

  return 0;
}

static int vale_bpf_config(struct nm_ifreq *req) {
  int ret;
  struct vale_bpf_req *r = (struct vale_bpf_req *)req->data;

  switch (r->method) {
    case LOAD_PROG:
      ret = vale_bpf_load_prog(r->prog_data.code,
          r->prog_data.code_len, r->prog_data.jit);
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
  vm = ebpf_create();
  if (vm == NULL) {
    return -ENOMEM;
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

  ebpf_destroy(vm);
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
MODULE_DEPEND(vale_bpf, ebpf, 1, 1, 1);

#else
#error Unsupported platform
#endif
