/*
 * Copyright 2017 Yutaro Hayakawa
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 */

#include <linux/bpf.h>
#include <linux/kernel.h>
#include <linux/cpumask.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <bsd_glue.h>

#include <net/netmap.h>
#include <dev/netmap/netmap_kern.h> /* XXX Provide path in Makefile */

#include <net/vale_bpf_native.h>
#include <net/vale_bpf_proto.h>

/* 
 * eBPF context struct for vale-bpf. This is conpatible with context
 * struct for XDP(struct xdp_buff), so, we can load bpf program for
 * vale-bpf as program for XDP.
 */
struct vale_bpf_buf {
  void *data;
  void *data_end;
  void *data_hard_start; // unused
};

static struct bpf_prog *prog = NULL;
static struct bpf_map *meta_map = NULL;

/*
 * FIXME: We can't make sure that type of this f.file->provate_data
 * is really struct bpf_map or not, because we can't see bpf_map_fops
 * from kernel module.
 *
 * So, if userspace program passes wrong file descripter, kernel
 * maybe crashes.
 */
static struct bpf_map *get_meta_map_from_fd(int fd) {
  struct fd f = fdget(fd);
  struct bpf_map *map;

  map = (struct bpf_map *)(f.file->private_data);

  /* Increase refcount, but before it, we need to check limit */
  if (atomic_inc_return(&map->refcnt) > 32768) {
    atomic_dec(&map->refcnt);
    return ERR_PTR(-EBUSY);
  }

  fdput(f);

  return map;
}

static u_int vale_bpf_native_lookup(struct nm_bdg_fwd *ft, uint8_t *hint,
                             struct netmap_vp_adapter *vpna) {
  int err, ret;
  struct vale_bpf_buf vale_bpf;

  vale_bpf.data = (void *)ft->ft_buf;
  vale_bpf.data_end = (void *)(ft->ft_buf + (ptrdiff_t)ft->ft_len);
  vale_bpf.data_hard_start = (void *)ft->ft_buf; // head room allocation is not supported

  if (meta_map) {
    /* set src port */
    err = meta_map->ops->map_update_elem(meta_map, &(uint32_t){0}, &(uint32_t){vpna->bdg_port}, 0);
  }

  if (prog) {
    ret = bpf_prog_run_xdp(prog, (struct xdp_buff *)&vale_bpf);
  } else {
    ret = VALE_BPF_DROP;
  }

  return (u_int)ret;
}

static int vale_bpf_native_install_prog(int prog_fd, int meta_map_fd) {
  struct bpf_prog *p;
  struct bpf_map *m;

  p = bpf_prog_get_type(prog_fd, BPF_PROG_TYPE_XDP);
  if (IS_ERR(p)) {
    return PTR_ERR(p);
  }

  m = get_meta_map_from_fd(meta_map_fd);
  if (IS_ERR(m)) {
    bpf_prog_put(p);
    return -1;
  }

  prog = p;
  meta_map = m;

  D("Loaded bpf program");

  return 0;
}

static int vale_bpf_native_uninstall_prog(void) {
  bpf_prog_put(prog);
  prog = NULL;
  atomic_dec(&meta_map->refcnt);
  meta_map = NULL;
  return 0;
}

static int vale_bpf_native_config(struct nm_ifreq *req) {
  int ret;
  struct vale_bpf_native_req *r = (struct vale_bpf_native_req *)req->data; 

  switch (r->method) {
    case INSTALL_PROG:
      if (r->len != sizeof(struct vale_bpf_native_install_req)) {
        D("Invalid argument length");
        return -1;
      }

      ret = vale_bpf_native_install_prog(r->install_req.prog_fd,
          r->install_req.meta_map_fd);
      if (ret < 0) {
        D("Installation of bpf program failed");
      }
      break;
    case UNINSTALL_PROG:
      ret = vale_bpf_native_uninstall_prog(); // always returns zero
      break;
    default:
      D("No such method");
      return -1;
  }
  return ret;
}

static struct netmap_bdg_ops vale_bpf_native_ops = {vale_bpf_native_lookup, vale_bpf_native_config, NULL};

static int vale_bpf_native_init(void) {
  struct nmreq nmr;

  bzero(&nmr, sizeof(nmr));
  nmr.nr_version = NETMAP_API;
  strlcpy(nmr.nr_name, VALE_NAME, sizeof(nmr.nr_name));
  strlcat(nmr.nr_name, ":", sizeof(nmr.nr_name));
  nmr.nr_cmd = NETMAP_BDG_REGOPS;
  if (netmap_bdg_ctl(&nmr, &vale_bpf_native_ops)) {
    D("create a bridge named %s beforehand using vale-ctl", nmr.nr_name);
    return -ENOENT;
  }

  D("Loaded vale-bpf-native-" VALE_NAME);

  return 0;
}

static void vale_bpf_native_fini(void) {
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

  if (prog) {
    bpf_prog_put(prog);
  }

  D("Unloaded vale-bpf-native-" VALE_NAME);
}

module_init(vale_bpf_native_init);
module_exit(vale_bpf_native_fini);
MODULE_AUTHOR("Yutaro Hayakawa");
MODULE_DESCRIPTION("VALE BPF Native Module");
MODULE_LICENSE("GPL");
