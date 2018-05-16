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

int vale_bpf_init(void);
void vale_bpf_fini(void);
