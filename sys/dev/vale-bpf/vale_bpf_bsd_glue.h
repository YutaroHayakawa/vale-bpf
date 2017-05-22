#ifndef _VALE_BPF_BSD_GLUE_H_
#define _VALE_BPF_BSD_GLUE_H_

/* endianness macros/functions */
#define htobe64 cpu_to_be64
#define htole16 cpu_to_le16

/* TODO delete this code */
#define nm_os_malloc(s) kmalloc(s, GFP_KERNEL)
#define nm_os_free(m) kfree(m)

#endif
