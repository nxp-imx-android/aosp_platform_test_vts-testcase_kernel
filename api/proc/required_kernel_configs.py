#!/usr/bin/env python
#
# Copyright (C) 2017 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

"""Required kernel configuration options for Treble.

    TODO(jaeshin): Uncomment configs that are temporarily commented out
    (# marlin) to ensure the testCheckConfigs test passes, once the marlin
    kernel is updated.
    TODO(jaeshin): Consolidate new config requirements with android-base.cfg

    Kernel configuration requirements are specified in android-base.cfg

    Key: config_name
    Value: config_state
        "y": enabled, represents both "y" and "m" options
        "n": should not be set
"""

CONFIGS = {
    # Loadable Kernel Modules
    # "CONFIG_MODULES": "y", # marlin
    # "CONFIG_MODULE_UNLOAD": "y", # marlin
    # "CONFIG_MODVERSIONS": "y", # marlin
    # "CONFIG_MODULE_SIG": "y", # marlin
    # "CONFIG_MODULE_SIG_FORCE": "y", # marlin

    # Device Tree Support
    "CONFIG_OF": "y",
    # "CONFIG_OF_*": "y",
    # "CONFIG_PROC_DEVICETREE": "y", # for kernels prior to 3.15

    # procfs
    "CONFIG_PROC_FS": "y",
    "CONFIG_PROC_SYSCTL": "y",
    "CONFIG_PROC_PAGE_MONITOR": "y",
    "CONFIG_PROC_PID_CPUSET": "y",
    "CONFIG_IKCONFIG": "y",
    "CONFIG_IKCONFIG_PROC": "y",

    # sysfs
    "CONFIG_SYSFS": "y",
    "CONFIG_SYSFS_DEPRECATED": "n",

    # debugfs
    # "CONFIG_DEBUG_FS": "n", # marlin

    # selinuxfs
    # "CONFIG_SECURITY_SELINUX": "y", # duplicated below in android-base.cfg

    # cgroups
    # "CONFIG_CGROUPS": "y", # duplicated below in android-base.cfg
    "CONFIG_CGROUP_DEBUG": "n",

    # memory
    # "CONFIG_MEMCG": "y", # marlin

    # cpu
    # "CONFIG_CGROUP_SCHED": "y", # duplicated below in android-base.cfg
    # "CONFIG_RT_GROUP_SCHED": "y", # duplicated below in android-base.cfg
    # "CONFIG_FAIR_GROUP_SCHED": "y",  # optional

    # cpuacct
    # "CONFIG_CGROUP_CPUACCT": "y", # duplicated below in android-base.cfg

    # cpuset
    "CONFIG_CPUSETS": "y",
    # "CONFIG_PROC_PID_CPUSET": "y", # nice to have

    # schedtune
    "CONFIG_SCHED_TUNE": "y",

    # pstore fs (PENDING confirmation from kernel team)
    # "CONFIG_PSTORE": "y",
    # "CONFIG_PSTORE_*": "y", # differs depending on your hardware, enable the ones present

    # functionfs
    # "CONFIG_USB_FUNCTIONFS": "y", # marlin
    # "CONFIG_USB_*": "y", # possibly a few more

    # android-base.cfg configs from
    # https://android.googlesource.com/kernel/common/+/android-4.4/android/configs/android-base.cfg
    "CONFIG_DEVKMEM": "n",
    "CONFIG_DEVMEM": "n",
    "CONFIG_INET_LRO": "n",
    "CONFIG_OABI_COMPAT": "n",
    "CONFIG_SYSVIPC": "n",
    "CONFIG_ANDROID": "y",
    "CONFIG_ANDROID_BINDER_IPC": "y",
    "CONFIG_ANDROID_LOW_MEMORY_KILLER": "y",
    "CONFIG_ARMV8_DEPRECATED": "y",
    "CONFIG_ASHMEM": "y",
    "CONFIG_AUDIT": "y",
    "CONFIG_BLK_DEV_DM": "y",
    "CONFIG_BLK_DEV_INITRD": "y",
    "CONFIG_CGROUPS": "y",
    "CONFIG_CGROUP_CPUACCT": "y",
    "CONFIG_CGROUP_FREEZER": "y",
    "CONFIG_CGROUP_SCHED": "y",
    # "CONFIG_CP15_BARRIER_EMULATION": "y", # marlin
    "CONFIG_DM_CRYPT": "y",
    "CONFIG_DM_VERITY": "y",
    "CONFIG_DM_VERITY_FEC": "y",
    "CONFIG_EMBEDDED": "y",
    "CONFIG_FB": "y",
    "CONFIG_HARDENED_USERCOPY": "y",
    "CONFIG_HIGH_RES_TIMERS": "y",
    "CONFIG_INET6_AH": "y",
    "CONFIG_INET6_ESP": "y",
    "CONFIG_INET6_IPCOMP": "y",
    "CONFIG_INET": "y",
    "CONFIG_INET_DIAG_DESTROY": "y",
    "CONFIG_INET_ESP": "y",
    "CONFIG_INET_XFRM_MODE_TUNNEL": "y",
    "CONFIG_IP6_NF_FILTER": "y",
    "CONFIG_IP6_NF_IPTABLES": "y",
    "CONFIG_IP6_NF_MANGLE": "y",
    "CONFIG_IP6_NF_RAW": "y",
    "CONFIG_IP6_NF_TARGET_REJECT": "y",
    "CONFIG_IPV6": "y",
    "CONFIG_IPV6_MIP6": "y",
    "CONFIG_IPV6_MULTIPLE_TABLES": "y",
    "CONFIG_IPV6_OPTIMISTIC_DAD": "y",
    # "CONFIG_IPV6_PRIVACY": "y", # marlin
    "CONFIG_IPV6_ROUTER_PREF": "y",
    "CONFIG_IPV6_ROUTE_INFO": "y",
    "CONFIG_IP_ADVANCED_ROUTER": "y",
    # "CONFIG_IP_MULTICAST": "y", # marlin
    "CONFIG_IP_MULTIPLE_TABLES": "y",
    "CONFIG_IP_NF_ARPFILTER": "y",
    "CONFIG_IP_NF_ARPTABLES": "y",
    "CONFIG_IP_NF_ARP_MANGLE": "y",
    "CONFIG_IP_NF_FILTER": "y",
    "CONFIG_IP_NF_IPTABLES": "y",
    "CONFIG_IP_NF_MANGLE": "y",
    "CONFIG_IP_NF_MATCH_AH": "y",
    "CONFIG_IP_NF_MATCH_ECN": "y",
    "CONFIG_IP_NF_MATCH_TTL": "y",
    "CONFIG_IP_NF_NAT": "y",
    "CONFIG_IP_NF_RAW": "y",
    "CONFIG_IP_NF_SECURITY": "y",
    "CONFIG_IP_NF_TARGET_MASQUERADE": "y",
    "CONFIG_IP_NF_TARGET_NETMAP": "y",
    "CONFIG_IP_NF_TARGET_REDIRECT": "y",
    "CONFIG_IP_NF_TARGET_REJECT": "y",
    "CONFIG_NET": "y",
    "CONFIG_NETDEVICES": "y",
    "CONFIG_NETFILTER": "y",
    # "CONFIG_NETFILTER_TPROXY": "y", # marlin
    "CONFIG_NETFILTER_XT_MATCH_COMMENT": "y",
    "CONFIG_NETFILTER_XT_MATCH_CONNLIMIT": "y",
    "CONFIG_NETFILTER_XT_MATCH_CONNMARK": "y",
    "CONFIG_NETFILTER_XT_MATCH_CONNTRACK": "y",
    "CONFIG_NETFILTER_XT_MATCH_HASHLIMIT": "y",
    "CONFIG_NETFILTER_XT_MATCH_HELPER": "y",
    "CONFIG_NETFILTER_XT_MATCH_IPRANGE": "y",
    "CONFIG_NETFILTER_XT_MATCH_LENGTH": "y",
    "CONFIG_NETFILTER_XT_MATCH_LIMIT": "y",
    "CONFIG_NETFILTER_XT_MATCH_MAC": "y",
    "CONFIG_NETFILTER_XT_MATCH_MARK": "y",
    "CONFIG_NETFILTER_XT_MATCH_PKTTYPE": "y",
    "CONFIG_NETFILTER_XT_MATCH_POLICY": "y",
    "CONFIG_NETFILTER_XT_MATCH_QTAGUID": "y",
    "CONFIG_NETFILTER_XT_MATCH_QUOTA2": "y",
    # "CONFIG_NETFILTER_XT_MATCH_QUOTA2_LOG": "y", # marlin
    "CONFIG_NETFILTER_XT_MATCH_QUOTA": "y",
    "CONFIG_NETFILTER_XT_MATCH_SOCKET": "y",
    "CONFIG_NETFILTER_XT_MATCH_STATE": "y",
    "CONFIG_NETFILTER_XT_MATCH_STATISTIC": "y",
    "CONFIG_NETFILTER_XT_MATCH_STRING": "y",
    "CONFIG_NETFILTER_XT_MATCH_TIME": "y",
    "CONFIG_NETFILTER_XT_MATCH_U32": "y",
    "CONFIG_NETFILTER_XT_TARGET_CLASSIFY": "y",
    "CONFIG_NETFILTER_XT_TARGET_CONNMARK": "y",
    "CONFIG_NETFILTER_XT_TARGET_CONNSECMARK": "y",
    "CONFIG_NETFILTER_XT_TARGET_IDLETIMER": "y",
    "CONFIG_NETFILTER_XT_TARGET_MARK": "y",
    "CONFIG_NETFILTER_XT_TARGET_NFLOG": "y",
    "CONFIG_NETFILTER_XT_TARGET_NFQUEUE": "y",
    "CONFIG_NETFILTER_XT_TARGET_SECMARK": "y",
    "CONFIG_NETFILTER_XT_TARGET_TCPMSS": "y",
    "CONFIG_NETFILTER_XT_TARGET_TPROXY": "y",
    "CONFIG_NETFILTER_XT_TARGET_TRACE": "y",
    "CONFIG_NET_CLS_ACT": "y",
    "CONFIG_NET_CLS_U32": "y",
    "CONFIG_NET_EMATCH": "y",
    "CONFIG_NET_EMATCH_U32": "y",
    "CONFIG_NET_KEY": "y",
    "CONFIG_NET_SCHED": "y",
    "CONFIG_NET_SCH_HTB": "y",
    "CONFIG_NF_CONNTRACK": "y",
    "CONFIG_NF_CONNTRACK_AMANDA": "y",
    "CONFIG_NF_CONNTRACK_EVENTS": "y",
    "CONFIG_NF_CONNTRACK_FTP": "y",
    "CONFIG_NF_CONNTRACK_H323": "y",
    "CONFIG_NF_CONNTRACK_IPV4": "y",
    "CONFIG_NF_CONNTRACK_IPV6": "y",
    "CONFIG_NF_CONNTRACK_IRC": "y",
    "CONFIG_NF_CONNTRACK_NETBIOS_NS": "y",
    "CONFIG_NF_CONNTRACK_PPTP": "y",
    "CONFIG_NF_CONNTRACK_SANE": "y",
    "CONFIG_NF_CONNTRACK_SECMARK": "y",
    "CONFIG_NF_CONNTRACK_TFTP": "y",
    "CONFIG_NF_CT_NETLINK": "y",
    "CONFIG_NF_CT_PROTO_DCCP": "y",
    "CONFIG_NF_CT_PROTO_SCTP": "y",
    "CONFIG_NF_CT_PROTO_UDPLITE": "y",
    "CONFIG_NF_NAT": "y",
    "CONFIG_NO_HZ": "y",
    "CONFIG_PACKET": "y",
    "CONFIG_PM_AUTOSLEEP": "y",
    "CONFIG_PM_WAKELOCKS": "y",
    "CONFIG_PPP": "y",
    "CONFIG_PPPOLAC": "y",
    "CONFIG_PPPOPNS": "y",
    "CONFIG_PPP_BSDCOMP": "y",
    "CONFIG_PPP_DEFLATE": "y",
    "CONFIG_PPP_MPPE": "y",
    "CONFIG_PREEMPT": "y",
    "CONFIG_PROFILING": "y",
    "CONFIG_QFMT_V2": "y",
    "CONFIG_QUOTA": "y",
    "CONFIG_QUOTA_NETLINK_INTERFACE": "y",
    "CONFIG_QUOTA_TREE": "y",
    "CONFIG_QUOTACTL": "y",
    # "CONFIG_RANDOMIZE_BASE": "y", # marlin
    "CONFIG_RTC_CLASS": "y",
    "CONFIG_RT_GROUP_SCHED": "y",
    "CONFIG_SECCOMP": "y",
    "CONFIG_SECURITY": "y",
    "CONFIG_SECURITY_NETWORK": "y",
    "CONFIG_SECURITY_PERF_EVENTS_RESTRICT": "y",
    "CONFIG_SECURITY_SELINUX": "y",
    # "CONFIG_SETEND_EMULATION": "y", # marlin
    "CONFIG_STAGING": "y",
    "CONFIG_SWP_EMULATION": "y",
    "CONFIG_SYNC": "y",
    "CONFIG_TUN": "y",
    # "CONFIG_UID_CPUTIME": "y", # marlin
    "CONFIG_UNIX": "y",
    "CONFIG_USB_GADGET": "y",
    # "CONFIG_USB_CONFIGFS": "y", # marlin
    # "CONFIG_USB_CONFIGFS_F_FS": "y", # marlin
    # "CONFIG_USB_CONFIGFS_F_MTP": "y", # marlin
    # "CONFIG_USB_CONFIGFS_F_PTP": "y", # marlin
    # "CONFIG_USB_CONFIGFS_F_ACC": "y", # marlin
    # "CONFIG_USB_CONFIGFS_F_AUDIO_SRC": "y", # marlin
    # "CONFIG_USB_CONFIGFS_UEVENT": "y", # marlin
    # "CONFIG_USB_CONFIGFS_F_MIDI": "y", # marlin
    # "CONFIG_USB_OTG_WAKELOCK": "y", # marlin
    "CONFIG_XFRM_USER": "y",
}
