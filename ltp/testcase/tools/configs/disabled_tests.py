# Disabled tests
DISABLED_TESTS = [
    'can.can_filter_32bit',  # b/191224815
    'can.can_filter_64bit',  # b/191224815
    'can.can_rcv_own_msgs_32bit',  # b/191225491
    'can.can_rcv_own_msgs_64bit',  # b/191225491
    'commands.file01_sh_32bit',  # b/191227027
    'commands.file01_sh_64bit',  # b/191227027
    'commands.ldd01_sh_32bit',  # b/191227033
    'commands.ldd01_sh_64bit',  # b/191227033
    'commands.mkdir01_sh_32bit',  # b/191224340
    'commands.mkdir01_sh_64bit',  # b/191224340
    'commands.unshare01_sh_32bit',  # b/191225496
    'commands.unshare01_sh_64bit',  # b/191225496
    'commands.unzip01_sh_32bit',  # b/191227036
    'commands.unzip01_sh_64bit',  # b/191227036
    'controllers.cgroup_fj_function_blkio_32bit',  # b/191224883
    'controllers.cgroup_fj_function_blkio_64bit',  # b/191224883
    'controllers.cgroup_fj_function_memory_32bit',  # b/191867109
    'controllers.cgroup_fj_function_memory_64bit',  # b/191867109
    'controllers.cgroup_fj_function_net_prio_32bit', # b/193172511
    'controllers.cgroup_fj_function_net_prio_64bit', # b/193172511
    'controllers.memcg_control_32bit', #b/197942864
    'controllers.memcg_control_64bit', #b/197942864
    'controllers.memcg_regression_32bit', #b/199506772
    'controllers.memcg_regression_64bit', #b/199506772
    'controllers.memcg_test_3_32bit', #b/199506772
    'controllers.memcg_test_3_64bit', #b/199506772
    'cve.cve-2017-15649_32bit',  # b/191224884
    'cve.cve-2017-15649_64bit',  # b/191224884
    'cve.cve-2017-2636_32bit',  # b/191224903
    'cve.cve-2017-2636_64bit',  # b/191224903
    'cve.cve-2019-8912_32bit',  # b/191224904
    'cve.cve-2019-8912_64bit',  # b/191224904
    'cve.cve-2020-14416_32bit',  # b/191227026
    'cve.cve-2020-14416_64bit',  # b/191227026
    'cve.cve-2021-3444_32bit',  # b/191226866
    'cve.cve-2021-3444_64bit',  # b/191226866
    'kernel_misc.zram01_32bit',  # b/191226875
    'kernel_misc.zram01_64bit',  # b/191226875
    'kernel_misc.zram02_32bit',  # b/191227531
    'kernel_misc.zram02_64bit',  # b/191227531
    'pty.pty03_32bit',  # b/191224822
    'pty.pty03_64bit',  # b/191224822
    'pty.pty05_32bit',  # b/191224341
    'pty.pty05_64bit',  # b/191224341
    'sched.sched_getattr01_32bit', # b/200686092
    'sched.sched_setattr01_32bit', # b/200686092
    'syscalls.bpf_prog02_32bit',  # b/191867447
    'syscalls.bpf_prog02_64bit',  # b/191867447
    'syscalls.bpf_prog05_32bit',  # b/191224899
    'syscalls.bpf_prog05_64bit',  # b/191224899
    'syscalls.clone301_32bit',  # b/191236153
    'syscalls.clone301_64bit',  # b/191236153
    'syscalls.clone302_32bit',  # b/191236103
    'syscalls.clone302_64bit',  # b/191236103
    'syscalls.copy_file_range02_64bit',  # b/191236491
    'syscalls.fcntl38_32bit',  # b/191236494
    'syscalls.fcntl38_64_32bit',  # b/191236432
    'syscalls.fcntl38_64_64bit',  # b/191236432
    'syscalls.fcntl38_64bit',  # b/191236494
    'syscalls.ftruncate04_32bit',  # b/198611142
    'syscalls.ftruncate04_64_32bit',  # b/198611142
    'syscalls.ftruncate04_64_64bit',  # b/198611142
    'syscalls.ftruncate04_64bit',  # b/198611142
    'syscalls.inotify07_32bit',  # b/191773884
    'syscalls.inotify07_64bit',  # b/191773884
    'syscalls.inotify08_32bit',  # b/191748474
    'syscalls.inotify08_64bit',  # b/191748474
    'syscalls.io_pgetevents01_32bit',  # b/191247131
    'syscalls.io_pgetevents02_32bit',  # b/191247132
    'syscalls.ioctl_loop01_32bit',  # b/191224819
    'syscalls.ioctl_loop01_64bit',  # b/191224819
    'syscalls.ioctl_loop02_32bit',  # b/191227028
    'syscalls.ioctl_loop02_64bit',  # b/191227028
    'syscalls.ioctl_loop07_32bit',  # b/191748892
    'syscalls.ioctl_loop07_64bit',  # b/191748892, b/191227029
    'syscalls.ioctl_ns01_32bit',  # b/191227031
    'syscalls.ioctl_ns01_64bit',  # b/191227031
    'syscalls.ioctl_ns04_32bit',  # b/191225494
    'syscalls.ioctl_ns04_64bit',  # b/191225494
    'syscalls.ioctl_ns05_32bit',  # b/191226869
    'syscalls.ioctl_ns05_64bit',  # b/191226869
    'syscalls.ioctl_ns06_32bit',  # b/191224339
    'syscalls.ioctl_ns06_64bit',  # b/191224339
    'syscalls.madvise06_32bit',  # b/191227034
    'syscalls.madvise06_64bit',  # b/191227034
    'syscalls.rt_sigprocmask01_32bit',  # b/191248975
    'syscalls.rt_sigtimedwait01_32bit',  # b/191247810
    'syscalls.sched_getattr01_32bit', # b/200686092
    'syscalls.sched_setattr01_32bit', # b/200686092
    'syscalls.semctl09_32bit',  # b/191227035
    'syscalls.semctl09_64bit',  # b/191227035
    'syscalls.shmctl08_32bit',  # b/191227526
    'syscalls.shmctl08_64bit',  # b/191227526
    'syscalls.statx07_32bit',  # b/191236106
    'syscalls.statx07_64bit',  # b/191236106
]

# These tests are only disabled for hwasan
DISABLED_TESTS_HWASAN = [
    'commands.sysctl02_sh_64bit',  # b/191227527
    'fs.binfmt_misc01_64bit',  # b/191224879
    'fs.binfmt_misc02_64bit',  # b/191224881
    'fs.read_all_dev_64bit',  # b/191226872
    'fs.read_all_proc_64bit',  # b/191226873
    'syscalls.accept02_64bit',  # b/191224729
]
