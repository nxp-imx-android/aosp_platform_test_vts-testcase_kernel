/*
 * Copyright (C) 2018 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "kern.h"
#include <linux/bpf.h>
#include <stdint.h>
#include "bpf_helpers.h"

struct bpf_map_def SEC("maps") test_configuration_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(uint32_t),
    .max_entries = 1,
};

struct bpf_map_def SEC("maps") test_stats_map_A = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(uint64_t),
    .value_size = sizeof(struct stats_value),
    .max_entries = NUM_SOCKETS,
};

struct bpf_map_def SEC("maps") test_stats_map_B = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(uint64_t),
    .value_size = sizeof(struct stats_value),
    .max_entries = NUM_SOCKETS,
};

static inline void bpf_update_stats(struct __sk_buff* skb, void* map) {
  uint64_t sock_cookie = bpf_get_socket_cookie(skb);
  struct stats_value* value;
  value = bpf_map_lookup_elem(map, &sock_cookie);
  if (!value) {
    struct stats_value newValue = {};
    bpf_map_update_elem(map, &sock_cookie, &newValue, BPF_NOEXIST);
    value = bpf_map_lookup_elem(map, &sock_cookie);
  }
  if (value) {
    __sync_fetch_and_add(&value->rxPackets, 1);
    __sync_fetch_and_add(&value->rxBytes, skb->len);
  }
}

SEC("skfilter/test")
int ingress_prog(struct __sk_buff* skb) {
  uint32_t key = 1;
  uint32_t* config = bpf_map_lookup_elem(&test_configuration_map, &key);
  if (config) {
    if (*config) {
      bpf_update_stats(skb, &test_stats_map_A);
    } else {
      bpf_update_stats(skb, &test_stats_map_B);
    }
  }
  return skb->len;
}

char _license[] SEC("license") = "Apache 2.0";
