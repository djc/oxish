//! Terminal backed by a pseudoconsole (ConPTY) on Windows

use core::{
    future::Future,
    pin::Pin,
    ptr,
    sync::atomic::{AtomicU64, Ordering},
    task::{Context, Poll, ready},
};
use std::{
    collections::BTreeMap,
    env, io,
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
        process::ExitStatusExt,
    },
    path::{Path, PathBuf},
    process,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
};

use proto::channels::{PtyReq, WindowChange};
use tokio::{
    net::windows::named_pipe::{ClientOptions, NamedPipeClient},
    task::JoinHandle,
};
use tracing::{debug, warn};
use windows::{
    Win32::{
        Foundation::{CloseHandle, ERROR_BROKEN_PIPE, ERROR_PIPE_NOT_CONNECTED, HANDLE},
        Storage::FileSystem::{
            FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_INBOUND, PIPE_ACCESS_OUTBOUND,
        },
        System::{
            Console::{COORD, ClosePseudoConsole, CreatePseudoConsole, HPCON, ResizePseudoConsole},
            Pipes::{
                CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE,
                PIPE_WAIT,
            },
            Threading::{
                CREATE_UNICODE_ENVIRONMENT, CreateProcessW, EXTENDED_STARTUPINFO_PRESENT,
                GetExitCodeProcess, INFINITE, PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
                PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOEXW, TerminateProcess,
                WaitForSingleObject,
            },
        },
    },
    core::{PCWSTR, PWSTR},
};

use super::{
    process::{Attribute, AttributeList},
    security::{SecurityAttributes, current_sid},
    utils::wide,
};

// Declaration order is drop order, and our pipe ends have to go before the console: the flush
// `ClosePseudoConsole()` does then finds a broken pipe rather than waiting to be read
pub(crate) struct Terminal {
    input: NamedPipeClient,
    output: NamedPipeClient,
    console: Arc<PseudoConsole>,
    process: Arc<OwnedHandle>,
    exit: Option<JoinHandle<()>>,
}

impl Terminal {
    pub(crate) fn spawn(req: &PtyReq<'_>, env: &[(String, String)]) -> io::Result<Self> {
        debug!(?req, ?env, "spawning new session with a pseudoconsole");
        if !req.terminal_modes.is_empty() {
            debug!("ignoring terminal modes: a pseudoconsole has no termios to set");
        }

        let sid = current_sid()?;
        let attributes = SecurityAttributes::restricted(&sid)?;

        let name = format!(
            r"\\.\pipe\oxish-pty-{}-{}",
            process::id(),
            NEXT_PIPE.fetch_add(1, Ordering::Relaxed)
        );
        let (input, input_console) = pipe(&format!("{name}-in"), &attributes, Direction::ToShell)?;
        let (output, output_console) =
            pipe(&format!("{name}-out"), &attributes, Direction::FromShell)?;

        // SAFETY: both console ends are alive for the call.
        let handle = unsafe {
            CreatePseudoConsole(
                size(req.cols, req.rows),
                HANDLE(input_console.as_raw_handle()),
                HANDLE(output_console.as_raw_handle()),
                0,
            )
        }?;

        // The pseudoconsole has duplicates of both console ends now, and ours have to go: a write
        // end left open here would hold the output pipe open past the console, so a reader would
        // never see the shell go away.
        drop((input_console, output_console));
        let console = Arc::new(PseudoConsole(Mutex::new(Some(handle))));
        let process = match start_shell(handle, env, &req.term) {
            Ok(shell) => Arc::new(shell),
            // Our ends go first here too, so the console's flush has nothing left to wait for.
            Err(error) => {
                drop((input, output));
                return Err(error);
            }
        };

        let exit = tokio::task::spawn_blocking({
            let (console, process) = (Arc::clone(&console), Arc::clone(&process));
            move || {
                // SAFETY: `process` owns the handle for the length of the wait.
                unsafe { WaitForSingleObject(HANDLE(process.as_raw_handle()), INFINITE) };
                console.close();
            }
        });

        Ok(Self {
            input,
            output,
            console,
            process,
            exit: Some(exit),
        })
    }

    /// Resize the pseudoconsole window (in response to a window-change request)
    pub(crate) fn resize(&self, change: &WindowChange) -> io::Result<()> {
        debug!(?change, "resizing pseudoconsole window");
        self.console.resize(size(change.cols, change.rows))
    }

    /// Write data to the pseudoconsole (sends input to the shell)
    pub(crate) async fn write(&self, data: &[u8]) -> io::Result<()> {
        let mut rest = data;
        while !rest.is_empty() {
            self.input.writable().await?;
            match self.input.try_write(rest) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(written) => rest = &rest[written..],
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                Err(error) => return Err(error),
            }
        }

        Ok(())
    }

    /// Read data from the pseudoconsole (receives output from the shell)
    pub(crate) fn poll_read(
        &mut self,
        buf: &mut [u8],
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<usize>> {
        loop {
            if let Err(error) = ready!(self.output.poll_read_ready(cx)) {
                return Poll::Ready(eof(error));
            }

            match self.output.try_read(buf) {
                Ok(read) => return Poll::Ready(Ok(read)),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                Err(error) => return Poll::Ready(eof(error)),
            }
        }
    }

    /// Wait for the shell process to exit, yielding the status it exited with
    pub(crate) fn poll_wait(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<process::ExitStatus>> {
        // Taken once it completes, because a finished wait cannot be polled again
        if let Some(exit) = &mut self.exit {
            if let Err(error) = ready!(Pin::new(exit).poll(cx)) {
                return Poll::Ready(Err(io::Error::other(error)));
            }

            self.exit = None;
        }

        // The wait is over, so this is the code the shell exited with and not `STILL_ACTIVE`.
        let mut code = 0;
        // SAFETY: `process` owns the handle, which is alive for the call, and `code` is valid
        // for writes.
        unsafe { GetExitCodeProcess(HANDLE(self.process.as_raw_handle()), &mut code) }?;
        Poll::Ready(Ok(process::ExitStatus::from_raw(code)))
    }

    /// Terminate the shell process
    ///
    /// Use [`Self::poll_wait()`] after calling this to pick up its exit status.
    pub(crate) fn start_kill(&mut self) {
        if let Err(error) = self.terminate() {
            warn!(%error, "error killing terminal");
        }
    }

    fn terminate(&self) -> windows::core::Result<()> {
        // SAFETY: `process` owns the handle, which is alive until this returns.
        unsafe { TerminateProcess(HANDLE(self.process.as_raw_handle()), 1) }
    }
}

impl Drop for Terminal {
    fn drop(&mut self) {
        // TODO: take the shell's own children down with it. Windows has no session to signal the
        // way a controlling terminal does elsewhere, so this reaches the shell alone and whatever
        // it started outlives the session. A job object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`,
        // joined while the shell is still suspended and held here, is the shape that covers it.

        // Terminating a process that has already exited fails, which is nothing to act on.
        let _ = self.terminate();

        // The kill above releases the waiter, and closing the console is left to it. Doing that
        // here would hang instead: our end of the output pipe is still in place with nothing
        // reading it, so the flush `ClosePseudoConsole()` does would wait forever.
    }
}

/// The pseudoconsole letting go of the output pipe is the shell gone, which is end of file
fn eof(error: io::Error) -> io::Result<usize> {
    let code = error.raw_os_error();
    if code == Some(ERROR_BROKEN_PIPE.0 as i32) || code == Some(ERROR_PIPE_NOT_CONNECTED.0 as i32) {
        Ok(0)
    } else {
        Err(error)
    }
}

/// Which way data flows over a pipe
enum Direction {
    FromShell,
    ToShell,
}

/// One of the pseudoconsole's pipes: our end, and the server end the console is given
///
/// A pipe has to be named to be opened for overlapped I/O, which is what driving our end from
/// the runtime takes; the console reads and writes its own end synchronously. Opening ours
/// connects the instance, so the console never waits for a client.
///
/// The name is in a namespace any local process can reach, so the access control list is what
/// keeps a session's terminal to the account it belongs to.
fn pipe(
    name: &str,
    attributes: &SecurityAttributes,
    direction: Direction,
) -> io::Result<(NamedPipeClient, OwnedHandle)> {
    let access = match direction {
        Direction::ToShell => PIPE_ACCESS_INBOUND,
        Direction::FromShell => PIPE_ACCESS_OUTBOUND,
    };

    // SAFETY: the name is null-terminated and the attributes are read during the call.
    let console = unsafe {
        CreateNamedPipeW(
            PCWSTR(wide(name).as_ptr()),
            access | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            BUFFER,
            BUFFER,
            0,
            Some(attributes.as_ptr()),
        )
    };
    if console.is_invalid() {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: the call succeeded, so the handle is ours to close.
    let console = unsafe { OwnedHandle::from_raw_handle(console.0) };
    let client = ClientOptions::new()
        .read(matches!(direction, Direction::FromShell))
        .write(matches!(direction, Direction::ToShell))
        .open(name)?;

    Ok((client, console))
}

/// Start the shell attached to the pseudoconsole, and take ownership of the process
fn start_shell(console: HPCON, env: &[(String, String)], term: &str) -> io::Result<OwnedHandle> {
    let shell = shell();
    debug!(?shell, "starting shell");

    // `CreateProcessW()` may write to the command line it is given, so it cannot be const.
    let mut command = wide(format!("\"{}\"", shell.display()));
    let environment = environment(env, term);
    let directory = env::var_os("USERPROFILE").map(wide);
    let attributes = AttributeList::new(&[Attribute {
        kind: PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE as usize,
        value: ptr::without_provenance(console.0 as usize),
        len: size_of::<HPCON>(),
    }])?;

    let mut startup = STARTUPINFOEXW::default();
    startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
    startup.lpAttributeList = attributes.as_ptr();
    // Claiming the standard handles and giving none is what holds the shell to the pseudoconsole;
    // without this it takes the console this process was started from.
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;

    let mut info = PROCESS_INFORMATION::default();
    // SAFETY: every buffer passed in is live and null-terminated, and the attribute list is
    // initialized
    unsafe {
        CreateProcessW(
            None,
            Some(PWSTR(command.as_mut_ptr())),
            None,
            None,
            false,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT,
            Some(environment.as_ptr().cast()),
            directory
                .as_ref()
                .map_or(PCWSTR::null(), |dir| PCWSTR(dir.as_ptr())),
            ptr::from_ref(&startup).cast(),
            &mut info,
        )
    }?;

    // SAFETY: the call succeeded, so both handles are ours to close; only the process is kept.
    unsafe {
        CloseHandle(info.hThread)?;
        Ok(OwnedHandle::from_raw_handle(info.hProcess.0))
    }
}

/// The shell a session runs
fn shell() -> PathBuf {
    let system_root = env::var_os("SystemRoot").unwrap_or_else(|| SYSTEM_ROOT.into());
    Path::new(&system_root).join(POWERSHELL)
}

/// The environment block for the shell: this process's, with the client's layered on top
///
/// The block is sorted by name, case-insensitively, as its format documents. A nul ends one
/// variable and starts the next, so anything the client asked for that carries one would set
/// variables it was never allowed to, and is dropped whole instead.
fn environment(env: &[(String, String)], term: &str) -> Vec<u16> {
    let client = env.iter().map(|(name, value)| (&**name, &**value));
    let term = (!term.is_empty()).then_some(("TERM", term));

    let mut vars = BTreeMap::new();
    for (name, value) in env::vars_os() {
        vars.insert(name.to_string_lossy().to_uppercase(), (name, value));
    }

    for (name, value) in client.chain(term) {
        if name.contains('\0') || value.contains('\0') {
            debug!(name, "ignoring environment variable containing a nul");
            continue;
        }

        vars.insert(name.to_uppercase(), (name.into(), value.into()));
    }

    let mut block = Vec::new();
    for (name, value) in vars.into_values() {
        block.extend(name.encode_wide());
        block.push(u16::from(b'='));
        block.extend(value.encode_wide());
        block.push(0);
    }

    block.push(0);
    block
}

/// A zero dimension means the client left it unspecified (RFC 4254 section 6.2)
///
/// `CreatePseudoConsole()` refuses that with `ERROR_INVALID_PARAMETER`, so it becomes what a
/// terminal that says nothing about itself usually is.
fn size(cols: u32, rows: u32) -> COORD {
    COORD {
        X: dimension(cols, DEFAULT_COLS),
        Y: dimension(rows, DEFAULT_ROWS),
    }
}

/// A `COORD` is signed and 16 bits wide, so a client may ask for more than one can hold
fn dimension(value: u32, default: i16) -> i16 {
    match value {
        0 => default,
        value => value.min(i16::MAX as u32) as i16,
    }
}

/// A pseudoconsole handle, closed exactly once
struct PseudoConsole(Mutex<Option<HPCON>>);

impl PseudoConsole {
    fn resize(&self, size: COORD) -> io::Result<()> {
        match *self.lock() {
            None => Ok(()),
            // SAFETY: the lock holds the handle open for the length of the call.
            Some(console) => Ok(unsafe { ResizePseudoConsole(console, size) }?),
        }
    }

    fn close(&self) {
        if let Some(console) = self.lock().take() {
            // SAFETY: the handle is taken out from under the lock, so this runs once.
            unsafe { ClosePseudoConsole(console) };
        }
    }

    /// A panic elsewhere says nothing about the handle, which is either open or not
    fn lock(&self) -> MutexGuard<'_, Option<HPCON>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Drop for PseudoConsole {
    fn drop(&mut self) {
        self.close();
    }
}

/// What each pipe buffers, the 64 KiB the standard library gives a child process's pipes
///
/// Room here is what keeps the flush `ClosePseudoConsole()` does from waiting to be read.
const BUFFER: u32 = 64 * 1024;

const DEFAULT_COLS: i16 = 80;
const DEFAULT_ROWS: i16 = 24;

const SYSTEM_ROOT: &str = r"C:\Windows";
const POWERSHELL: &str = r"System32\WindowsPowerShell\v1.0\powershell.exe";

static NEXT_PIPE: AtomicU64 = AtomicU64::new(0);

#[cfg(test)]
mod tests {
    use super::environment;

    /// A nul the client hid in a variable it was allowed to set must not become another one
    #[test]
    fn a_client_variable_cannot_carry_a_nul() {
        let env = [
            ("LC_ALL".to_string(), "en_US\0PATH=C:\\evil".to_string()),
            ("LANG".to_string(), "en_US.UTF-8".to_string()),
        ];

        let block = String::from_utf16_lossy(&environment(&env, "xterm\0PATH=C:\\evil"));
        let variables = block.split('\0').filter(|var| !var.is_empty());
        for variable in variables {
            assert!(
                !variable.starts_with("PATH=C:\\evil"),
                "client set {variable:?}"
            );
        }
    }
}
