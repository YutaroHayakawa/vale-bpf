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

#include <dev/ebpf/ebpf_platform.h>
#include <dev/ebpf_dev/ebpf_dev_platform.h>
#include <dev/vale-bpf/vale_bpf_platform.h>

#include <net/netmap.h>
#include <dev/netmap/netmap_kern.h>
#include <sys/ebpf_vm.h>

#include <net/vale_bpf.h>

static int jit_enable = 1;
static struct ebpf_vm *vale_bpf_vm = NULL;
static ebpf_file_t *running_prog = NULL;

static uint32_t
vale_bpf_lookup(struct nm_bdg_fwd *ft, uint8_t *ring_nr,
    struct netmap_vp_adapter *vpna, void *pd)
{
  uint64_t ret = NM_BDG_NOPORT;
  struct vale_bpf_md md;

  // FIXME: Drop packets from indirect buffer.
  if (ft->ft_flags & NS_INDIRECT) {
    return NM_BDG_NOPORT;
  }

  md.data = (uintptr_t)ft->ft_buf + ft->ft_offset;
  md.data_end = (uintptr_t)md.data + ft->ft_len - ft->ft_offset;
  md.ingress_port = vpna->bdg_port;
  md.ring_nr = *ring_nr;

  /*
   * We don't have to check if vale_bpf_vm == NULL or not,
   * because ebpf_exec_* returns UINT64_MAX in that case.
   */

  ebpf_epoch_enter();

  if (jit_enable) {
    ret = ebpf_exec_jit(vale_bpf_vm, &md, sizeof(md));
  } else {
    ret = ebpf_exec(vale_bpf_vm, &md, sizeof(md));
  }

  ebpf_epoch_exit();

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

  if (ebpf_register(ret, 1, "ebpf_map_update_elem", ebpf_map_update_elem)) {
    goto err;
  }

  if (ebpf_register(ret, 2, "ebpf_map_lookup_elem", ebpf_map_lookup_elem)) {
    goto err;
  }

  if (ebpf_register(ret, 3, "ebpf_map_delete_elem", ebpf_map_delete_elem)) {
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
  int ret = 0;
  struct vale_bpf_req *r = (struct vale_bpf_req *)req->data;

  switch (r->method) {
    case VALE_BPF_LOAD_PROG:
      ret = vale_bpf_load_prog(r->ebpf_prog_fd);
      break;
    case VALE_BPF_UNLOAD_PROG:
      vale_bpf_unload_prog();
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

int
vale_bpf_init(void)
{
  int error;

  error = netmap_bdg_regops(VALE_NAME":", &vale_bpf_ops, NULL, NULL);
  if (error) {
    D("create a bridge named %s beforehand using vale-ctl", VALE_NAME);
    return error;
  }

  D("Loaded vale-bpf-" VALE_NAME);

  return 0;
}

void
vale_bpf_fini(void)
{
  int error;

  error = netmap_bdg_regops(VALE_NAME":", NULL, NULL, NULL);
  if (error) {
    D("failed to release VALE bridge");
  }

  D("Unloaded vale-bpf-" VALE_NAME);

  if (vale_bpf_vm) {
    vale_bpf_unload_prog();
  }
}
