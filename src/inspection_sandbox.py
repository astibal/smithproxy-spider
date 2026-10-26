"""Kernel-enforced worker policy. Install before compiling any submitted script.

This is containment, not a Python object/import blacklist. Even ctypes calls are
subject to Landlock and seccomp. Unsupported hosts fail closed.
"""
import ctypes
import errno
import fcntl
import os
import platform
import sysconfig


class SandboxUnavailable(RuntimeError):
    pass


def install_script_sandbox(storage_directory=None):
    if platform.system() != 'Linux' or platform.machine() not in ('x86_64', 'aarch64'):
        raise SandboxUnavailable('Script sandbox requires Linux x86_64 or aarch64')

    # Load the native storage implementation before restricting dynamic loading.
    import sqlite3
    import math
    import zlib
    import _strptime

    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    try:
        seccomp = ctypes.CDLL('libseccomp.so.2', use_errno=True)
    except OSError as error:
        raise SandboxUnavailable('Script sandbox requires libseccomp.so.2') from error

    # Linux syscall numbers shared by the two supported architectures.
    create, add_rule, restrict = 444, 445, 446
    abi = libc.syscall(create, 0, 0, 1)
    if abi < 3:
        raise SandboxUnavailable('Script sandbox requires Landlock ABI >= 3 (including truncate)')

    class Ruleset(ctypes.Structure):
        _fields_ = [('handled_access_fs', ctypes.c_uint64)]

    class PathRule(ctypes.Structure):
        _pack_ = 1
        _fields_ = [('allowed_access', ctypes.c_uint64), ('parent_fd', ctypes.c_int32)]

    # Handle all filesystem rights through ABI 3; newer device ioctl rights
    # are denied independently by the syscall allowlist below.
    handled = (1 << 15) - 1
    read_only = (1 << 2) | (1 << 3)  # READ_FILE, READ_DIR
    storage_access = read_only | sum(1 << bit for bit in (1, 4, 5, 7, 8, 13, 14))
    paths = {os.path.realpath(sysconfig.get_path(key)): read_only
             for key in ('stdlib', 'platstdlib')}

    if storage_directory:
        storage = os.path.realpath(storage_directory)
        if os.path.islink(os.path.abspath(storage_directory)) or storage == '/' or any(
                os.path.commonpath((storage, path)) == storage for path in paths):
            raise SandboxUnavailable('Storage must be a dedicated directory, not a runtime ancestor')
        os.makedirs(storage, mode=0o700, exist_ok=True)
        paths[os.path.realpath(storage)] = storage_access

    ruleset = Ruleset(handled)
    fd = libc.syscall(create, ctypes.byref(ruleset), ctypes.sizeof(ruleset), 0)
    if fd < 0:
        raise SandboxUnavailable('Cannot create Landlock ruleset')

    try:
        for path, rights in paths.items():
            parent = os.open(path, os.O_PATH | os.O_CLOEXEC)
            try:
                rule = PathRule(rights, parent)
                if libc.syscall(add_rule, fd, 1, ctypes.byref(rule), 0) != 0:
                    raise SandboxUnavailable('Cannot add Landlock path rule')
            finally:
                os.close(parent)

        if libc.prctl(38, 1, 0, 0, 0) != 0:  # PR_SET_NO_NEW_PRIVS
            raise SandboxUnavailable('Cannot enable no_new_privs')
        if libc.syscall(restrict, fd, 0) != 0:
            raise SandboxUnavailable('Cannot enforce Landlock ruleset')
    finally:
        os.close(fd)

    seccomp.seccomp_init.argtypes = [ctypes.c_uint32]
    seccomp.seccomp_init.restype = ctypes.c_void_p
    seccomp.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    seccomp.seccomp_rule_add.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint]
    seccomp.seccomp_load.argtypes = [ctypes.c_void_p]
    seccomp.seccomp_release.argtypes = [ctypes.c_void_p]

    class Argument(ctypes.Structure):
        _fields_ = [('arg', ctypes.c_uint), ('op', ctypes.c_int),
                    ('value', ctypes.c_uint64), ('unused', ctypes.c_uint64)]

    seccomp.seccomp_rule_add_array.argtypes = [ctypes.c_void_p, ctypes.c_uint32,
                                              ctypes.c_int, ctypes.c_uint,
                                              ctypes.POINTER(Argument)]
    policy = seccomp.seccomp_init(0x00050000 | errno.EPERM)  # default: deny
    if not policy:
        raise SandboxUnavailable('Cannot create seccomp filter')

    try:
        # File access is further restricted by Landlock. No sockets, processes,
        # signals to other processes, ptrace, mount, io_uring or kernel APIs.
        allowed = '''read write readv writev pread64 pwrite64 close close_range
            lseek fstat newfstatat stat lstat statx access faccessat faccessat2
            open openat getdents64 readlink readlinkat getcwd
            flock fsync fdatasync ftruncate truncate
            mkdir mkdirat unlink unlinkat rename renameat renameat2
            mmap mprotect munmap mremap brk madvise
            rt_sigaction rt_sigprocmask rt_sigreturn sigaltstack
            futex set_robust_list rseq
            clock_gettime clock_getres gettimeofday time nanosleep clock_nanosleep
            getpid getppid gettid getuid geteuid getgid getegid getrandom
            sched_yield sched_getaffinity uname getrusage
            exit exit_group'''.split()
        for name in allowed:
            number = seccomp.seccomp_syscall_resolve_name(name.encode())
            if number >= 0 and seccomp.seccomp_rule_add(policy, 0x7fff0000, number, 0) != 0:
                raise SandboxUnavailable('Cannot allow syscall: ' + name)

        # SQLite needs advisory locks and Python needs descriptor flags. Do not
        # allow F_SETOWN/F_SETSIG/F_SETLEASE: they can arrange cross-process signals.
        number = seccomp.seccomp_syscall_resolve_name(b'fcntl')
        commands = (fcntl.F_DUPFD, fcntl.F_DUPFD_CLOEXEC, fcntl.F_GETFD, fcntl.F_SETFD,
                    fcntl.F_GETFL, fcntl.F_SETFL, fcntl.F_GETLK, fcntl.F_SETLK, fcntl.F_SETLKW)
        for command in commands:
            argument = Argument(1, 4, command, 0)  # argument 1 == command
            if seccomp.seccomp_rule_add_array(policy, 0x7fff0000, number, 1, ctypes.byref(argument)) != 0:
                raise SandboxUnavailable('Cannot allow safe fcntl command')

        if seccomp.seccomp_load(policy) != 0:
            raise SandboxUnavailable('Cannot enforce seccomp filter')
    finally:
        seccomp.seccomp_release(policy)
