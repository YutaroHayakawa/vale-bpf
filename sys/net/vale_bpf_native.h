#ifndef _VALE_BPF_NATIVE_H_
#define _VALE_BPF_NATIVE_H_

#include <uapi/linux/vale_bpf_common.h>

struct vale_bpf_md {
  __u32 data;
  __u32 data_end;
};

#endif
