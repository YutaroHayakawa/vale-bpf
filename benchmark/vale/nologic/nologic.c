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

static uint32_t
nologic_lookup(struct nm_bdg_fwd *ft, uint8_t *ring_nr,
    struct netmap_vp_adapter *vpna, void *pd)
{
  return 1;
}

static struct netmap_bdg_ops nologic_ops = {
  .lookup = nologic_lookup,
};

static int
nologic_init(void)
{
  int error;

  error = netmap_bdg_regops(VALE_NAME":", &nologic_ops, NULL, NULL);
  if (error) {
    D("create a bridge named %s beforehand using vale-ctl", VALE_NAME);
    return error;
  }

  D("Loaded nologic-" VALE_NAME);

  return 0;
}

static void
nologic_fini(void)
{
  int error;

  error = netmap_bdg_regops(VALE_NAME":", NULL, NULL, NULL);
  if (error) {
    D("failed to release VALE bridge");
  }

  D("Unloaded nologic-" VALE_NAME);
}

#if defined(linux)

module_init(nologic_init);
module_exit(nologic_fini);
MODULE_AUTHOR("Yutaro Hayakawa");
MODULE_DESCRIPTION("Nologic");
MODULE_LICENSE("Apache2");

#elif defined(__FreeBSD__)

static int
nologic_loader(module_t mod, int type, void *data)
{
  int error = 0;

  switch (type) {
  case MOD_LOAD:
    error = nologic_init();
    break;
  case MOD_UNLOAD:
    nologic_fini();
    break;
  default:
    error = EINVAL;
    break;
  }

  return error;
}

DEV_MODULE(nologic, nologic_loader, NULL);
MODULE_DEPEND(vale_bpf, netmap, 1, 1, 1);

#endif
