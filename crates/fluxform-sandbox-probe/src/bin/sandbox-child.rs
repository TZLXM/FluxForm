#[cfg(not(target_os = "linux"))]
fn main() {
    std::process::exit(125);
}

#[cfg(target_os = "linux")]
fn probe_ipv4_socket_denial(port: u16) -> bool {
    let socket = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if socket < 0 {
        return std::io::Error::last_os_error().raw_os_error() == Some(libc::EACCES);
    }

    let address = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: port.to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(std::net::Ipv4Addr::LOCALHOST.octets()),
        },
        sin_zero: [0; 8],
    };
    unsafe {
        libc::connect(
            socket,
            (&address as *const libc::sockaddr_in).cast(),
            std::mem::size_of_val(&address) as libc::socklen_t,
        );
        libc::close(socket);
    }
    false
}

#[cfg(target_os = "linux")]
fn probe_ipv6_socket_denial(port: u16) -> bool {
    let socket = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if socket < 0 {
        return std::io::Error::last_os_error().raw_os_error() == Some(libc::EACCES);
    }

    let address = libc::sockaddr_in6 {
        sin6_family: libc::AF_INET6 as libc::sa_family_t,
        sin6_port: port.to_be(),
        sin6_flowinfo: 0,
        sin6_addr: libc::in6_addr {
            s6_addr: std::net::Ipv6Addr::LOCALHOST.octets(),
        },
        sin6_scope_id: 0,
    };
    unsafe {
        libc::connect(
            socket,
            (&address as *const libc::sockaddr_in6).cast(),
            std::mem::size_of_val(&address) as libc::socklen_t,
        );
        libc::close(socket);
    }
    false
}

#[cfg(target_os = "linux")]
fn probe_packet_socket_denial() -> bool {
    let socket = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if socket < 0 {
        return std::io::Error::last_os_error().raw_os_error() == Some(libc::EACCES);
    }
    unsafe { libc::close(socket) };
    false
}

#[cfg(target_os = "linux")]
fn probe_connect_denial() -> bool {
    let socket = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if socket < 0 {
        return false;
    }

    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let abstract_name = b"fluxform-connect-denial";
    for (target, source) in address.sun_path[1..1 + abstract_name.len()]
        .iter_mut()
        .zip(abstract_name)
    {
        *target = *source as libc::c_char;
    }
    let address_len =
        (std::mem::size_of::<libc::sa_family_t>() + 1 + abstract_name.len()) as libc::socklen_t;
    let result = unsafe {
        libc::connect(
            socket,
            (&address as *const libc::sockaddr_un).cast(),
            address_len,
        )
    };
    let error = std::io::Error::last_os_error().raw_os_error();
    unsafe { libc::close(socket) };
    result < 0 && error == Some(libc::EACCES)
}

#[cfg(target_os = "linux")]
fn probe_socketpair_denial() -> bool {
    let mut pair = [-1; 2];
    let result = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            0,
            pair.as_mut_ptr(),
        )
    };
    if result < 0 {
        return std::io::Error::last_os_error().raw_os_error() == Some(libc::EACCES);
    }
    unsafe {
        libc::close(pair[0]);
        libc::close(pair[1]);
    }
    false
}

#[cfg(target_os = "linux")]
fn probe_bpf_denial() -> bool {
    let result = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            0_u32,
            std::ptr::null_mut::<libc::c_void>(),
            0_u32,
        )
    };
    result < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EACCES)
}

#[cfg(target_os = "linux")]
fn probe_userfaultfd_denial() -> bool {
    let result =
        unsafe { libc::syscall(libc::SYS_userfaultfd, libc::O_CLOEXEC | libc::O_NONBLOCK) };
    if result < 0 {
        return std::io::Error::last_os_error().raw_os_error() == Some(libc::EACCES);
    }
    unsafe { libc::close(result as libc::c_int) };
    false
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct ProbeCloneArgs {
    flags: u64,
    pidfd: u64,
    child_tid: u64,
    parent_tid: u64,
    exit_signal: u64,
    stack: u64,
    stack_size: u64,
    tls: u64,
    set_tid: u64,
    set_tid_size: u64,
    cgroup: u64,
}

#[cfg(target_os = "linux")]
extern "C" fn clone_probe_exit(_argument: *mut libc::c_void) -> libc::c_int {
    0
}

#[cfg(target_os = "linux")]
fn probe_namespace_creation_denial() -> bool {
    let unshare_denied = unsafe { libc::unshare(libc::CLONE_NEWNET) } < 0
        && std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM);
    let setns_denied = unsafe { libc::setns(-1, libc::CLONE_NEWNET) } < 0
        && std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM);
    let clone_args = ProbeCloneArgs {
        flags: libc::CLONE_NEWNET as u64,
        pidfd: 0,
        child_tid: 0,
        parent_tid: 0,
        exit_signal: libc::SIGCHLD as u64,
        stack: 0,
        stack_size: 0,
        tls: 0,
        set_tid: 0,
        set_tid_size: 0,
        cgroup: 0,
    };
    let clone3_denied = unsafe {
        let result = libc::syscall(
            libc::SYS_clone3,
            &clone_args,
            std::mem::size_of::<ProbeCloneArgs>(),
        );
        result < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    };
    let mut stack = vec![0_u8; 64 * 1024];
    let stack_top = unsafe { stack.as_mut_ptr().add(stack.len()) };
    let stack_top = ((stack_top as usize) & !0xf) as *mut libc::c_void;
    let clone_denied = unsafe {
        let result = libc::clone(
            clone_probe_exit,
            stack_top,
            libc::CLONE_NEWNET | libc::SIGCHLD,
            std::ptr::null_mut(),
        );
        if result < 0 {
            std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
        } else {
            let mut status = 0;
            let _ = libc::waitpid(result, &mut status, 0);
            false
        }
    };
    unshare_denied && setns_denied && clone3_denied && clone_denied
}

#[cfg(target_os = "linux")]
fn main() {
    use std::fs::{self, File, OpenOptions};
    use std::io::Write;
    use std::os::fd::RawFd;
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::OpenOptionsExt;

    let mut arguments = std::env::args_os().skip(1);
    let Some(action) = arguments.next() else {
        std::process::exit(120);
    };

    let code = match action.to_string_lossy().as_ref() {
        "read-input" => match fs::read("/input") {
            Ok(bytes) if bytes == b"assigned-input" => 0,
            _ => 30,
        },
        "write-task" => {
            match File::create("result.bin").and_then(|mut file| file.write_all(b"task-output")) {
                Ok(()) => 0,
                Err(_) => 40,
            }
        }
        "read-path" => match arguments.next() {
            Some(path) if File::open(path).is_ok() => 30,
            Some(_) => 31,
            None => 120,
        },
        "symlink-read-path" => match arguments.next() {
            Some(path) => match std::os::unix::fs::symlink("/etc/passwd", &path) {
                Ok(()) if File::open(path).is_ok() => 30,
                Ok(()) => 31,
                Err(_) => 32,
            },
            None => 120,
        },
        "write-path" => match arguments.next() {
            Some(path)
                if OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(path)
                    .is_ok() =>
            {
                40
            }
            Some(_) => 41,
            None => 120,
        },
        "overwrite-path" => match arguments.next() {
            Some(path)
                if OpenOptions::new()
                    .write(true)
                    .truncate(true)
                    .open(path)
                    .is_ok() =>
            {
                42
            }
            Some(_) => 43,
            None => 120,
        },
        "read-fd" => match arguments
            .next()
            .and_then(|raw| raw.to_string_lossy().parse::<RawFd>().ok())
        {
            Some(fd) => {
                let mut byte = 0_u8;
                if unsafe { libc::read(fd, (&mut byte as *mut u8).cast(), 1) } == 1 {
                    50
                } else {
                    51
                }
            }
            None => 120,
        },
        "write-at-fd" => {
            let fd = arguments
                .next()
                .and_then(|raw| raw.to_string_lossy().parse::<RawFd>().ok());
            let name = arguments.next();
            match (fd, name) {
                (Some(fd), Some(name)) => {
                    let name = std::ffi::CString::new(name.into_vec());
                    match name {
                        Ok(name) => {
                            let file = unsafe {
                                libc::openat(
                                    fd,
                                    name.as_ptr(),
                                    libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC,
                                    0o600,
                                )
                            };
                            if file >= 0 {
                                unsafe { libc::close(file) };
                                60
                            } else {
                                61
                            }
                        }
                        Err(_) => 120,
                    }
                }
                _ => 120,
            }
        }
        "probe-network" => {
            let ipv4_port = arguments
                .next()
                .and_then(|raw| raw.to_string_lossy().parse::<u16>().ok());
            let ipv6_port = arguments
                .next()
                .and_then(|raw| raw.to_string_lossy().parse::<u16>().ok());
            match (ipv4_port, ipv6_port) {
                (Some(ipv4_port), Some(ipv6_port))
                    if probe_ipv4_socket_denial(ipv4_port)
                        && probe_ipv6_socket_denial(ipv6_port)
                        && probe_packet_socket_denial()
                        && probe_connect_denial()
                        && probe_socketpair_denial()
                        && probe_bpf_denial()
                        && probe_userfaultfd_denial()
                        && probe_namespace_creation_denial() =>
                {
                    0
                }
                _ => 70,
            }
        }
        _ => 120,
    };

    std::process::exit(code);
}
