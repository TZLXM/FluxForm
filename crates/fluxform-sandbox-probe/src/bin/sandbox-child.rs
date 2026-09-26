#[cfg(not(target_os = "linux"))]
fn main() {
    std::process::exit(125);
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
        _ => 120,
    };

    std::process::exit(code);
}
