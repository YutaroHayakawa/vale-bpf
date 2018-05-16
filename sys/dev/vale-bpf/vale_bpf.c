/*-
 * SPDX-License-Identifier: Apache License 2.0
 *
 * Copyright 2017-2018 Yutaro Hayakawa
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
#include <sys/sysctl.h>

#else

#error Unsupported platform

#endif

#include <net/netmap.h>
#include <dev/netmap/netmap_kern.h>
#include <dev/ebpf_dev/ebpf_dev_platform.h>
#include <sys/ebpf_vm.h>

#include <net/vale_bpf.h>

static int jit_enable = 0;
static struct ebpf_vm *vale_bpf_vm = NULL;
static ebpf_file_t *running_prog = NULL;

static uint32_t
vale_bpf_lookup(struct nm_bdg_fwd *ft, uint8_t *ring_nr,
    struct netmap_vp_adapter *vpna)
{
  uint64_t ret = NM_BDG_NOPORT;
  struct vale_bpf_md md;

  // FIXME: Drop packets from indirect buffer.
  if (ft->ft_flags & NS_INDIRECT) {
    return NM_BDG_NOPORT;
  }

  md.data = (uintptr_t)ft->ft_buf;
  md.data_end = (uintptr_t)ft->ft_buf + ft->ft_len;
  md.ingress_port = vpna->bdg_port;
  md.ring_nr = *ring_nr;

  if (jit_enable) {
    ret = ebpf_exec_jit(vale_bpf_vm, &md, sizeof(md));
  } else {
    ret = ebpf_exec(vale_bpf_vm, &md, sizeof(md));
  }

  // Error occurs inside the vm
  if (ret == UINT64_MAX) {
    return NM_BDG_NOPORT;
  }

  // eBPF changed ring index
  if (md.ring_nr != *ring_nr) {
    *ring_nr = md.ring_nr;
  }

  return (uint32_t)ret;
}

static struct ebpf_vm *
vale_bpf_create_vm(void)
{
  struct ebpf_vm *ret = ebpf_create();
  if (!ret) {
    return NULL;
  }

  if (ebpf_register(ret, 0, "ebpf_map_update_elem", ebpf_map_update_elem)) {
    goto err;
  }

  if (ebpf_register(ret, 1, "ebpf_map_lookup_elem", ebpf_map_lookup_elem)) {
    goto err;
  }

  if (ebpf_register(ret, 2, "ebpf_map_delete_elem", ebpf_map_delete_elem)) {
    goto err;
  }

  return ret;

err:
  ebpf_destroy(ret);
  return NULL;
}

static void
vale_bpf_unload_prog(void)
{
  ebpf_destroy(vale_bpf_vm);
  vale_bpf_vm = NULL;
  ebpf_fdrop(running_prog, ebpf_curthread());
  running_prog = NULL;
}

static int
vale_bpf_load_prog(int prog_fd)
{
  int error;

  if (vale_bpf_vm) {
    vale_bpf_unload_prog();
  }

  ebpf_file_t *f;
  error = ebpf_fget(ebpf_curthread(), prog_fd, &f);
  if (error) {
    return error;
  }

  struct ebpf_obj_prog *new_prog_obj =
    ebpf_objfile_get_container(f);
  if (!new_prog_obj) {
    error = EINVAL;
    goto err0;
  }

  vale_bpf_vm = vale_bpf_create_vm();
  if (!vale_bpf_vm) {
    error = ENOMEM;
    goto err0;
  }

  error = ebpf_load(vale_bpf_vm, new_prog_obj->prog.prog,
      new_prog_obj->prog.prog_len);
  if (error) {
    goto err1;
  }

  if (jit_enable) {
    ebpf_jit_fn fn = ebpf_compile(vale_bpf_vm);
    if (!fn) {
      goto err1;
    }
  }

  running_prog = f;

  return 0;

err1:
  ebpf_destroy(vale_bpf_vm);
  vale_bpf_vm = NULL;
err0:
  ebpf_fdrop(f, ebpf_curthread());
  return error;
}

static int
vale_bpf_config(struct nm_ifreq *req)
{
  int ret;
  struct vale_bpf_req *r = (struct vale_bpf_req *)req->data;

  switch (r->method) {
    case VALE_BPF_LOAD_PROG:
      ret = vale_bpf_load_prog(r->ebpf_prog_fd);
      break;
    case VALE_BPF_UNLOAD_PROG:
      vale_bpf_unload_prog();
      ret = 0;
      break;
    default:
      ret = ENOTSUP;
      break;
  }

  return ret;
}

static struct netmap_bdg_ops vale_bpf_ops = {
  vale_bpf_lookup,
  vale_bpf_config,
  NULL
};

static int
vale_bpf_init(void)
{
  struct nmreq nmr;

  // initialize vm
  vale_bpf_vm = vale_bpf_create_vm();
  if (vale_bpf_vm == NULL) {
    return -ENOMEM;
  }

  memset(&nmr, 0, sizeof(nmr));
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

static void
vale_bpf_fini(void)
{
  struct nmreq nmr;
  int error;
  struct netmap_bdg_ops tmp = {netmap_bdg_learning, NULL, NULL};

  memset(&nmr, 0, sizeof(nmr));
  nmr.nr_version = NETMAP_API;
  strlcpy(nmr.nr_name, VALE_NAME, sizeof(nmr.nr_name));
  strlcat(nmr.nr_name, ":", sizeof(nmr.nr_name));
  nmr.nr_cmd = NETMAP_BDG_REGOPS;

  error = netmap_bdg_ctl(&nmr, &tmp);
  if (error) {
    D("failed to release VALE bridge %d", error);
  }

  D("Unloaded vale-bpf-" VALE_NAME);

  ebpf_destroy(vale_bpf_vm);
}

#if defined(linux)

module_init(vale_bpf_init);
module_exit(vale_bpf_fini);
MODULE_AUTHOR("Yutaro Hayakawa");
MODULE_DESCRIPTION("VALE BPF Extension Module");
MODULE_LICENSE("Apache2");

#elif defined(__FreeBSD__)

static int
vale_bpf_loader(module_t mod, int type, void *data)
{
  int error = 0;

  switch (type) {
  case MOD_LOAD:
    error = vale_bpf_init();
    break;
  case MOD_UNLOAD:
    vale_bpf_fini();
    break;
  default:
    error = -EINVAL;
  }

  return -error;
}

DEV_MODULE(vale_bpf, vale_bpf_loader, NULL);
MODULE_DEPEND(vale_bpf, netmap, 1, 1, 1);
MODULE_DEPEND(vale_bpf, ebpf, 1, 1, 1);
MODULE_DEPEND(vale_bpf, ebpf_dev, 1, 1, 1);

#else
#error Unsupported platform
#endif
