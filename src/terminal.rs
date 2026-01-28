use core::{
    future::Future,
    task::{Context, Poll},
};
use std::{
    collections::BTreeMap,
    env,
    ffi::OsStr,
    fs::OpenOptions,
    io,
    os::{
        fd::{AsFd, OwnedFd},
        unix::ffi::OsStrExt,
    },
    pin::pin,
    task::ready,
};

use bitflags::Flags;
use rustix::{
    fs::OFlags,
    io::{read, write},
    process::{ioctl_tiocsctty, setsid},
    pty::{self, OpenptFlags},
    stdio::{dup2_stderr, dup2_stdin, dup2_stdout},
    termios::{
        self, ControlModes, InputModes, LocalModes, OptionalActions, OutputModes, SpecialCodeIndex,
        Winsize,
    },
};
use tokio::{
    io::unix::AsyncFd,
    process::{Child, Command},
};
use tracing::debug;

use crate::messages::{Mode, PtyReq};

pub(crate) struct Terminal {
    pty: AsyncFd<OwnedFd>,
    child: Child,
}

impl Terminal {
    pub(crate) fn spawn(req: &PtyReq<'_>, env: &[(String, String)]) -> io::Result<Self> {
        debug!(?req, ?env, "spawning new session with PTY");
        let controller = pty::openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY)?;
        pty::grantpt(&controller)?;
        pty::unlockpt(&controller)?;

        let user_path = pty::ptsname(&controller, Vec::new())?;

        // Capture values for pre_exec closure
        let winsize = Winsize {
            ws_col: req.cols as u16,
            ws_row: req.rows as u16,
            ws_xpixel: req.width_px as u16,
            ws_ypixel: req.height_px as u16,
        };
        let terminal_modes = req.terminal_modes.clone();

        let shell = env::var("SHELL").unwrap_or_else(|_| "/bin/sh".into());
        let mut cmd = Command::new(&shell);
        cmd.arg("-l");

        for (k, v) in env {
            cmd.env(k, v);
        }
        if !req.term.is_empty() {
            cmd.env("TERM", req.term.as_ref());
        }

        // SAFETY: pre_exec runs after fork but before exec.
        // We only use async-signal-safe operations.
        unsafe {
            cmd.pre_exec(move || {
                let path = OsStr::from_bytes(user_path.as_bytes());
                let user_fd = OpenOptions::new().read(true).write(true).open(path)?;

                debug!("setting PTY window size");
                termios::tcsetwinsize(&user_fd, winsize)?;

                debug!("applying terminal modes");
                apply_terminal_modes_inner(&user_fd, &terminal_modes)?;

                setsid()?;
                ioctl_tiocsctty(&user_fd)?;

                // Dup to stdin/stdout/stderr
                dup2_stdin(&user_fd)?;
                dup2_stdout(&user_fd)?;
                dup2_stderr(&user_fd)?;

                Ok(())
            });
        }

        let child = cmd.spawn()?;
        rustix::fs::fcntl_setfl(&controller, OFlags::NONBLOCK)?;
        Ok(Self {
            pty: AsyncFd::new(controller)?,
            child,
        })
    }

    /// Write data to the PTY (sends input to the shell)
    pub(crate) async fn write(&self, data: &[u8]) -> io::Result<usize> {
        loop {
            let mut guard = self.pty.writable().await?;
            let result = guard.try_io(|inner| {
                write(inner.get_ref(), data)
                    .map_err(|e| io::Error::from_raw_os_error(e.raw_os_error()))
            });

            match result {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }

    /// Read data from the PTY (receives output from the shell)
    pub(crate) fn poll_read(
        &mut self,
        buf: &mut [u8],
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<usize>> {
        loop {
            let mut guard = match ready!(self.pty.poll_read_ready_mut(cx)) {
                Ok(guard) => guard,
                Err(err) => return Poll::Ready(Err(err)),
            };

            let result = guard.try_io(|inner| {
                read(inner.get_ref(), &mut *buf)
                    .map_err(|e| io::Error::from_raw_os_error(e.raw_os_error()))
            });

            match result {
                Ok(result) => return Poll::Ready(result),
                Err(_would_block) => continue,
            }
        }
    }

    pub(crate) fn poll_kill(mut self, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        let future = self.child.kill();
        let pinned = pin!(future);
        pinned.poll(cx)
    }
}

/// Apply SSH terminal modes to a PTY.
///
/// Maps SSH terminal mode opcodes (RFC 4254) to POSIX termios settings.
fn apply_terminal_modes_inner<F: AsFd>(fd: F, modes: &BTreeMap<Mode, u32>) -> io::Result<()> {
    if modes.is_empty() {
        return Ok(());
    }

    debug!("getting current terminal attributes");
    let mut tio = termios::tcgetattr(&fd)?;
    for (&mode, &value) in modes {
        debug!(?mode, value, "applying terminal mode");
        match mode {
            // Special characters (control characters)
            Mode::VIntr => tio.special_codes[SpecialCodeIndex::VINTR] = value as u8,
            Mode::VQuit => tio.special_codes[SpecialCodeIndex::VQUIT] = value as u8,
            Mode::VErase => tio.special_codes[SpecialCodeIndex::VERASE] = value as u8,
            Mode::VKill => tio.special_codes[SpecialCodeIndex::VKILL] = value as u8,
            Mode::VEof => tio.special_codes[SpecialCodeIndex::VEOF] = value as u8,
            Mode::VEol => tio.special_codes[SpecialCodeIndex::VEOL] = value as u8,
            Mode::VEol2 => tio.special_codes[SpecialCodeIndex::VEOL2] = value as u8,
            Mode::VStart => tio.special_codes[SpecialCodeIndex::VSTART] = value as u8,
            Mode::VStop => tio.special_codes[SpecialCodeIndex::VSTOP] = value as u8,
            Mode::VSusp => tio.special_codes[SpecialCodeIndex::VSUSP] = value as u8,
            #[cfg(any(
                target_os = "macos",
                target_os = "ios",
                target_os = "freebsd",
                target_os = "dragonfly",
                target_os = "openbsd",
                target_os = "netbsd"
            ))]
            Mode::VDSusp => tio.special_codes[SpecialCodeIndex::VDSUSP] = value as u8,
            #[cfg(not(any(
                target_os = "macos",
                target_os = "ios",
                target_os = "freebsd",
                target_os = "dragonfly",
                target_os = "openbsd",
                target_os = "netbsd"
            )))]
            Mode::VDSusp => {} // Not available on Linux
            Mode::VReprint => tio.special_codes[SpecialCodeIndex::VREPRINT] = value as u8,
            Mode::VWErase => tio.special_codes[SpecialCodeIndex::VWERASE] = value as u8,
            Mode::VLNext => tio.special_codes[SpecialCodeIndex::VLNEXT] = value as u8,
            Mode::VFlush | Mode::VDiscard => {
                tio.special_codes[SpecialCodeIndex::VDISCARD] = value as u8
            }
            #[cfg(target_os = "linux")]
            Mode::VSwtch => tio.special_codes[SpecialCodeIndex::VSWTC] = value as u8,
            #[cfg(not(target_os = "linux"))]
            Mode::VSwtch => {} // VSWTC not available on macOS/BSDs
            #[cfg(any(
                target_os = "macos",
                target_os = "ios",
                target_os = "freebsd",
                target_os = "dragonfly",
                target_os = "openbsd",
                target_os = "netbsd"
            ))]
            Mode::VStatus => tio.special_codes[SpecialCodeIndex::VSTATUS] = value as u8,
            #[cfg(not(any(
                target_os = "macos",
                target_os = "ios",
                target_os = "freebsd",
                target_os = "dragonfly",
                target_os = "openbsd",
                target_os = "netbsd"
            )))]
            Mode::VStatus => {} // Not available on Linux

            // Input modes
            Mode::IgnPar => set_flag(&mut tio.input_modes, InputModes::IGNPAR, value),
            Mode::ParMrk => set_flag(&mut tio.input_modes, InputModes::PARMRK, value),
            Mode::INPck => set_flag(&mut tio.input_modes, InputModes::INPCK, value),
            Mode::IStrip => set_flag(&mut tio.input_modes, InputModes::ISTRIP, value),
            Mode::INlCr => set_flag(&mut tio.input_modes, InputModes::INLCR, value),
            Mode::IgnCr => set_flag(&mut tio.input_modes, InputModes::IGNCR, value),
            Mode::ICrNl => set_flag(&mut tio.input_modes, InputModes::ICRNL, value),
            #[cfg(target_os = "linux")]
            Mode::IUcLc => set_flag(&mut tio.input_modes, InputModes::IUCLC, value),
            #[cfg(not(target_os = "linux"))]
            Mode::IUcLc => {} // Not available on macOS/BSDs
            Mode::IxOn => set_flag(&mut tio.input_modes, InputModes::IXON, value),
            Mode::IxAny => set_flag(&mut tio.input_modes, InputModes::IXANY, value),
            Mode::IxOff => set_flag(&mut tio.input_modes, InputModes::IXOFF, value),
            Mode::IMaxBel => set_flag(&mut tio.input_modes, InputModes::IMAXBEL, value),
            #[cfg(any(target_os = "linux", target_os = "macos", target_os = "ios"))]
            Mode::IUtf8 => set_flag(&mut tio.input_modes, InputModes::IUTF8, value),
            #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "ios")))]
            Mode::IUtf8 => {} // Not available on some platforms

            // Local modes
            Mode::ISig => set_flag(&mut tio.local_modes, LocalModes::ISIG, value),
            Mode::ICanon => set_flag(&mut tio.local_modes, LocalModes::ICANON, value),
            #[cfg(target_os = "linux")]
            Mode::XCase => set_flag(&mut tio.local_modes, LocalModes::XCASE, value),
            #[cfg(not(target_os = "linux"))]
            Mode::XCase => {} // Not available on macOS/BSDs
            Mode::Echo => set_flag(&mut tio.local_modes, LocalModes::ECHO, value),
            Mode::EchoE => set_flag(&mut tio.local_modes, LocalModes::ECHOE, value),
            Mode::EchoK => set_flag(&mut tio.local_modes, LocalModes::ECHOK, value),
            Mode::EchoNl => set_flag(&mut tio.local_modes, LocalModes::ECHONL, value),
            Mode::NoFlsh => set_flag(&mut tio.local_modes, LocalModes::NOFLSH, value),
            Mode::TOStop => set_flag(&mut tio.local_modes, LocalModes::TOSTOP, value),
            Mode::IExten => set_flag(&mut tio.local_modes, LocalModes::IEXTEN, value),
            Mode::EchoCtl => set_flag(&mut tio.local_modes, LocalModes::ECHOCTL, value),
            Mode::EchoKe => set_flag(&mut tio.local_modes, LocalModes::ECHOKE, value),
            Mode::Pendin => set_flag(&mut tio.local_modes, LocalModes::PENDIN, value),

            // Output modes
            Mode::OPost => set_flag(&mut tio.output_modes, OutputModes::OPOST, value),
            #[cfg(target_os = "linux")]
            Mode::OLcUc => set_flag(&mut tio.output_modes, OutputModes::OLCUC, value),
            #[cfg(not(target_os = "linux"))]
            Mode::OLcUc => {} // Not available on macOS/BSDs
            Mode::ONlCr => set_flag(&mut tio.output_modes, OutputModes::ONLCR, value),
            Mode::OCrNl => set_flag(&mut tio.output_modes, OutputModes::OCRNL, value),
            Mode::ONoCr => set_flag(&mut tio.output_modes, OutputModes::ONOCR, value),
            Mode::ONlRet => set_flag(&mut tio.output_modes, OutputModes::ONLRET, value),

            // Control modes
            Mode::Cs7 => {
                tio.control_modes.remove(ControlModes::CSIZE);
                tio.control_modes.insert(ControlModes::CS7);
            }
            Mode::Cs8 => {
                tio.control_modes.remove(ControlModes::CSIZE);
                tio.control_modes.insert(ControlModes::CS8);
            }
            Mode::ParenB => set_flag(&mut tio.control_modes, ControlModes::PARENB, value),
            Mode::ParOdd => set_flag(&mut tio.control_modes, ControlModes::PARODD, value),

            // Baud rates
            Mode::TtyOpISpeed => {
                let _ = tio.set_input_speed(value);
            }
            Mode::TtyOpOSpeed => {
                let _ = tio.set_output_speed(value);
            }
        }
    }

    termios::tcsetattr(&fd, OptionalActions::Now, &tio)?;
    Ok(())
}

fn set_flag<T: Flags>(flags: &mut T, flag: T, value: u32) {
    match value {
        0 => flags.remove(flag),
        _ => flags.insert(flag),
    }
}
