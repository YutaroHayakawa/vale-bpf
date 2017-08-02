/*
 * Copyright 2015 Big Switch Networks, Inc
 *
 * Modified by Yutaro Hayakawa in 2017
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
#include <linux/slab.h>
#include <linux/types.h>
#include <uapi/linux/elf.h>
#include <bsd_glue.h>

#elif defined(__FreeBSD__)

#include <sys/types.h>
#include <sys/errno.h>
#include <sys/param.h>	/* defines used in kernel.h */
#include <sys/kernel.h>	/* types used in module initialization */
#include <sys/conf.h>	/* cdevsw struct, UID, GID */
#include <sys/sockio.h>
#include <sys/socketvar.h>	/* struct socket */
#include <sys/malloc.h>
#include <sys/poll.h>
#include <sys/rwlock.h>
#include <sys/socket.h> /* sockaddrs */
#include <sys/selinfo.h>
#include <sys/sysctl.h>
#include <net/if.h>
#include <net/if_var.h>
#include <net/bpf.h>		/* BIOCIMMEDIATE */
#include <machine/bus.h>	/* bus_dmamap_* */
#include <sys/endian.h>
#include <sys/refcount.h>
#include <sys/elf.h>

#else

#error Unsupported platform

#endif

#include <net/netmap.h>
#include <dev/netmap/netmap_kern.h>

#include <vale_bpf_int.h>

#define MAX_SECTIONS 32

#ifndef EM_BPF
#define EM_BPF 247
#endif

struct bounds {
  const void *base;
  uint64_t size;
};

struct section {
  const Elf64_Shdr *shdr;
  const void *data;
  uint64_t size;
};

static const void *bounds_check(struct bounds *bounds, uint64_t offset,
                                uint64_t size) {
  if (offset + size > bounds->size || offset + size < offset) {
    return NULL;
  }

  /* cast for non GNU code */
  return (const char *)bounds->base + offset;
}

int vale_bpf_load_elf(struct vale_bpf_vm *vm, const void *elf,
                      size_t elf_size) {
  struct bounds b = {.base = elf, .size = elf_size};
  void *text_copy = NULL;
  int i;

  const Elf64_Ehdr *ehdr = bounds_check(&b, 0, sizeof(*ehdr));
  if (!ehdr) {
    D("not enough data for ELF header");
    goto error;
  }

  if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG)) {
    D("wrong magic");
    goto error;
  }

  if (ehdr->e_ident[EI_CLASS] != ELFCLASS64) {
    D("wrong class");
    goto error;
  }

  if (ehdr->e_ident[EI_DATA] != ELFDATA2LSB) {
    D("wrong byte order");
    goto error;
  }

  if (ehdr->e_ident[EI_VERSION] != 1) {
    D("wrong version");
    goto error;
  }

  if (ehdr->e_ident[EI_OSABI] != ELFOSABI_NONE) {
    D("wrong OS ABI");
    goto error;
  }

  if (ehdr->e_type != ET_REL) {
    D("wrong type, expected relocatable");
    goto error;
  }

  if (ehdr->e_machine != EM_NONE && ehdr->e_machine != EM_BPF) {
    D("wrong machine, expected none or BPF, got %d", ehdr->e_machine);
    goto error;
  }

  if (ehdr->e_shnum > MAX_SECTIONS) {
    D("too many sections");
    goto error;
  }

  /* Parse section headers into an array */
  struct section sections[MAX_SECTIONS];
  for (i = 0; i < ehdr->e_shnum; i++) {
    const Elf64_Shdr *shdr =
        bounds_check(&b, ehdr->e_shoff + i * ehdr->e_shentsize, sizeof(*shdr));
    if (!shdr) {
      D("bad section header offset or size");
      goto error;
    }

    const void *data = bounds_check(&b, shdr->sh_offset, shdr->sh_size);
    if (!data) {
      D("bad section offset or size");
      goto error;
    }

    sections[i].shdr = shdr;
    sections[i].data = data;
    sections[i].size = shdr->sh_size;
  }

  /* Find first text section */
  int text_shndx = 0;
  for (i = 0; i < ehdr->e_shnum; i++) {
    const Elf64_Shdr *shdr = sections[i].shdr;
    if (shdr->sh_type == SHT_PROGBITS &&
        shdr->sh_flags == (SHF_ALLOC | SHF_EXECINSTR)) {
      text_shndx = i;
      break;
    }
  }

  if (!text_shndx) {
    D("text section not found");
    goto error;
  }

  struct section *text = &sections[text_shndx];

  /* May need to modify text for relocations, so make a copy */
  text_copy = vale_bpf_os_malloc(text->size);
  if (!text_copy) {
    D("failed to allocate memory");
    goto error;
  }
  memcpy(text_copy, text->data, text->size);

  /* Process each relocation section */
  for (i = 0; i < ehdr->e_shnum; i++) {
    struct section *rel = &sections[i];
    if (rel->shdr->sh_type != SHT_REL) {
      continue;
    } else if (rel->shdr->sh_info != text_shndx) {
      continue;
    }

    const Elf64_Rel *rs = rel->data;

    if (rel->shdr->sh_link >= ehdr->e_shnum) {
      D("bad symbol table section index");
      goto error;
    }

    struct section *symtab = &sections[rel->shdr->sh_link];
    const Elf64_Sym *syms = symtab->data;
    uint32_t num_syms = symtab->size / sizeof(syms[0]);

    if (symtab->shdr->sh_link >= ehdr->e_shnum) {
      D("bad string table section index");
      goto error;
    }

    struct section *strtab = &sections[symtab->shdr->sh_link];
    const char *strings = strtab->data;

    int j;
    for (j = 0; j < rel->size / sizeof(Elf64_Rel); j++) {
      const Elf64_Rel *r = &rs[j];

      if (ELF64_R_TYPE(r->r_info) != 2) {
        D("bad relocation type %llu", (unsigned long long)ELF64_R_TYPE(r->r_info));
        goto error;
      }

      uint32_t sym_idx = ELF64_R_SYM(r->r_info);
      if (sym_idx >= num_syms) {
        D("bad symbol index");
        goto error;
      }

      const Elf64_Sym *sym = &syms[sym_idx];

      if (sym->st_name >= strtab->size) {
        D("bad symbol name");
        goto error;
      }

      const char *sym_name = strings + sym->st_name;

      if (r->r_offset + 8 > text->size) {
        D("bad relocation offset");
        goto error;
      }

      unsigned int imm = vale_bpf_lookup_registered_function(vm, sym_name);
      if (imm == -1) {
        D("function '%s' not found", sym_name);
        goto error;
      }

      /* cast for non GNU code */
      *(uint32_t *)((char *)text_copy + r->r_offset + 4) = imm;
    }
  }

  int rv = vale_bpf_load(vm, text_copy, sections[text_shndx].size);
  vale_bpf_os_free(text_copy);
  return rv;

error:
  vale_bpf_os_free(text_copy);
  return -1;
}
