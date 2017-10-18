#ifndef _VALE_BPF_NATIVE_HELPER_H_
#define _VALE_BPF_NATIVE_HELPER_H_

/*
 * meta_map
 *
 * Some metadata given by vale-bpf-native is stored in this map.
 * 
 * index        data                  description
 * 0            source port           VALE port number which packet comes from
 *
 */
BPF_TABLE("percpu_array", uint32_t, uint32_t, meta_map, 256);

enum meta_map_idx {
  META_MAP_SRCPORT = 0
};

#endif /* _VALE_BPF_NATIVE_HELPER_H_ */
