//! Terminal backed by a pseudoconsole (ConPTY) on Windows

use core::{
    ffi::c_void,
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
    io::{AsyncRead, ReadBuf},
    net::windows::named_pipe::{ClientOptions, NamedPipeClient},
    task::JoinHandle,
};
use tracing::{debug, warn};
use windows::{
    Win32::{
        Foundation::{
            CloseHandle, ERROR_BROKEN_PIPE, ERROR_PIPE_NOT_CONNECTED, HANDLE, HLOCAL, LocalFree,
        },
        Security::{
            Authorization::{
                ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
            },
            PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
        },
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
                CREATE_UNICODE_ENVIRONMENT, CreateProcessW, DeleteProcThreadAttributeList,
                EXTENDED_STARTUPINFO_PRESENT, GetExitCodeProcess, INFINITE,
                InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST,
                PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, PROCESS_INFORMATION, STARTF_USESTDHANDLES,
                STARTUPINFOEXW, TerminateProcess, UpdateProcThreadAttribute, WaitForSingleObject,
            },
        },
    },
    core::{PCWSTR, PWSTR},
};

use super::{Buffer, current_sid, wide};

// Fields drop in declaration order. Our pipe ends must close before the console, so the flush in
// `ClosePseudoConsole()` hits a broken pipe instead of waiting for a reader.
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

        // The pseudoconsole duplicated both console ends. Close ours, or the output write end
        // keeps the pipe open after the shell exits and reads never reach end of file.
        drop((input_console, output_console));
        let console = Arc::new(PseudoConsole(Mutex::new(Some(handle))));
        let process = match start_shell(handle, env, &req.term) {
            Ok(shell) => Arc::new(shell),
            // Close our ends before the console, as in `Terminal`'s field order
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

    /// Resize the pseudoconsole
    pub(crate) fn resize(&self, change: &WindowChange) -> io::Result<()> {
        debug!(?change, "resizing pseudoconsole window");
        self.console.resize(size(change.cols, change.rows))
    }

    /// Write input to the shell
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

    /// Read output from the shell
    pub(crate) fn poll_read(
        &mut self,
        buf: &mut [u8],
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<usize>> {
        let mut buf = ReadBuf::new(buf);
        Poll::Ready(
            match ready!(Pin::new(&mut self.output).poll_read(cx, &mut buf)) {
                Ok(()) => Ok(buf.filled().len()),
                Err(error) => eof(error),
            },
        )
    }

    /// Wait for the shell process to exit, yielding the status it exited with
    pub(crate) fn poll_wait(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<process::ExitStatus>> {
        // A completed `JoinHandle` must not be polled again
        if let Some(exit) = &mut self.exit {
            if let Err(error) = ready!(Pin::new(exit).poll(cx)) {
                return Poll::Ready(Err(io::Error::other(error)));
            }

            self.exit = None;
        }

        // The shell has exited, so this is its exit code and not `STILL_ACTIVE`
        let mut code = 0;
        // SAFETY: `process` keeps the handle open, and `code` is valid for writes.
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
        // SAFETY: `process` keeps the handle open.
        unsafe { TerminateProcess(HANDLE(self.process.as_raw_handle()), 1) }
    }
}

impl Drop for Terminal {
    fn drop(&mut self) {
        // TODO: also kill the shell's children, which outlive the session today. Assigning the
        // shell to a job object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` before it runs would.

        // Fails if the shell already exited, which is fine
        let _ = self.terminate();

        // The waiter closes the console once the shell exits. Closing it here would hang: the
        // flush in `ClosePseudoConsole()` waits on our output pipe, which nothing reads.
    }
}

/// Treat the output pipe breaking, which means the shell exited, as end of file
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

/// Create a pseudoconsole pipe, returning our async end and the console's synchronous end
///
/// Only named pipes support the overlapped I/O tokio needs. Opening our end connects the pipe
/// before the console uses it. Any local process can open the name, so `attributes` limit
/// access to the session's account.
fn pipe(
    name: &str,
    attributes: &SecurityAttributes,
    direction: Direction,
) -> io::Result<(NamedPipeClient, OwnedHandle)> {
    let access = match direction {
        Direction::ToShell => PIPE_ACCESS_INBOUND,
        Direction::FromShell => PIPE_ACCESS_OUTBOUND,
    };

    // SAFETY: the name is null-terminated, and `attributes` outlives the call.
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

    // SAFETY: the call succeeded, so we own the handle.
    let console = unsafe { OwnedHandle::from_raw_handle(console.0) };
    let client = ClientOptions::new()
        .read(matches!(direction, Direction::FromShell))
        .write(matches!(direction, Direction::ToShell))
        .open(name)?;

    Ok((client, console))
}

/// Start the shell attached to the pseudoconsole
fn start_shell(console: HPCON, env: &[(String, String)], term: &str) -> io::Result<OwnedHandle> {
    let shell = shell();
    debug!(?shell, "starting shell");

    // `CreateProcessW()` may modify the command line, so it must be mutable
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
    // With no standard handles given, the shell uses the pseudoconsole instead of inheriting
    // this process's console
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;

    let mut info = PROCESS_INFORMATION::default();
    // SAFETY: every buffer is live and null-terminated, and the attribute list is initialized.
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

    // SAFETY: the call succeeded, so we own both handles.
    unsafe {
        CloseHandle(info.hThread)?;
        Ok(OwnedHandle::from_raw_handle(info.hProcess.0))
    }
}

/// The shell a session runs
pub(super) fn shell() -> PathBuf {
    let system_root = env::var_os("SystemRoot").unwrap_or_else(|| SYSTEM_ROOT.into());
    Path::new(&system_root).join(POWERSHELL)
}

/// Build the shell's environment block: this process's variables, overridden by the client's
///
/// The block must be sorted case-insensitively by name. Client variables containing a nul are
/// dropped, since a nul would split them into variables the client may not set.
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

/// Convert a requested terminal size to a `COORD`
///
/// A zero dimension means unspecified (RFC 4254 section 6.2), which `CreatePseudoConsole()`
/// rejects, so it falls back to 80x24.
fn size(cols: u32, rows: u32) -> COORD {
    COORD {
        X: dimension(cols, DEFAULT_COLS),
        Y: dimension(rows, DEFAULT_ROWS),
    }
}

/// Clamp `value` to the `i16` range of a `COORD`, with zero meaning `default`
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
            // SAFETY: holding the lock keeps the handle open.
            Some(console) => Ok(unsafe { ResizePseudoConsole(console, size) }?),
        }
    }

    fn close(&self) {
        if let Some(console) = self.lock().take() {
            // SAFETY: the handle was taken under the lock, so it is closed once.
            unsafe { ClosePseudoConsole(console) };
        }
    }

    /// Ignore poisoning, which cannot leave the handle in a bad state
    fn lock(&self) -> MutexGuard<'_, Option<HPCON>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Drop for PseudoConsole {
    fn drop(&mut self) {
        self.close();
    }
}

/// A [`SECURITY_ATTRIBUTES`] that owns the descriptor it points at
struct SecurityAttributes(SECURITY_ATTRIBUTES);

impl SecurityAttributes {
    /// Attributes granting full access to `sid` and SYSTEM only, with nothing inherited
    fn restricted(sid: &str) -> windows::core::Result<Self> {
        let sddl = wide(format!("D:P(A;;GA;;;{sid})(A;;GA;;;SY)"));
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        // SAFETY: `sddl` is null-terminated, and `descriptor` is valid for writes.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(sddl.as_ptr()),
                SDDL_REVISION_1,
                &mut descriptor,
                None,
            )
        }?;

        Ok(Self(SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: false.into(),
        }))
    }

    fn as_ptr(&self) -> *const SECURITY_ATTRIBUTES {
        ptr::from_ref(&self.0)
    }
}

impl Drop for SecurityAttributes {
    fn drop(&mut self) {
        // SAFETY: the descriptor was allocated with `LocalAlloc()`.
        unsafe { LocalFree(Some(HLOCAL(self.0.lpSecurityDescriptor))) };
    }
}

/// One attribute for a new process
struct Attribute {
    kind: usize,
    /// A pointer to the value, or for `PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE`, the value itself
    value: *const c_void,
    len: usize,
}

/// An initialized attribute list, valid until it is dropped
struct AttributeList(Buffer);

impl AttributeList {
    fn new(attributes: &[Attribute]) -> windows::core::Result<Self> {
        let count = attributes.len() as u32;
        let mut len = 0;
        // SAFETY: a null list only queries the required size.
        let _ = unsafe { InitializeProcThreadAttributeList(None, count, None, &mut len) };

        let buf = Buffer::new(len);
        let list = LPPROC_THREAD_ATTRIBUTE_LIST(buf.as_ptr().cast());
        // SAFETY: `buf` holds `len` bytes.
        unsafe { InitializeProcThreadAttributeList(Some(list), count, None, &mut len) }?;

        // Wrap it now so `Drop` deletes the list even if an update fails
        let list = Self(buf);
        for attribute in attributes {
            // SAFETY: the list is initialized with room for every attribute.
            unsafe {
                UpdateProcThreadAttribute(
                    list.as_ptr(),
                    0,
                    attribute.kind,
                    Some(attribute.value),
                    attribute.len,
                    None,
                    None,
                )
            }?;
        }

        Ok(list)
    }

    fn as_ptr(&self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        LPPROC_THREAD_ATTRIBUTE_LIST(self.0.as_ptr().cast())
    }
}

impl Drop for AttributeList {
    fn drop(&mut self) {
        // SAFETY: `new()` initialized the list.
        unsafe { DeleteProcThreadAttributeList(self.as_ptr()) };
    }
}

/// Pipe buffer size, the 64 KiB std uses for child process pipes
///
/// Enough room lets the flush in `ClosePseudoConsole()` finish without a reader.
const BUFFER: u32 = 64 * 1024;

const DEFAULT_COLS: i16 = 80;
const DEFAULT_ROWS: i16 = 24;

const SYSTEM_ROOT: &str = r"C:\Windows";
const POWERSHELL: &str = r"System32\WindowsPowerShell\v1.0\powershell.exe";

static NEXT_PIPE: AtomicU64 = AtomicU64::new(0);

#[cfg(test)]
mod tests {
    use super::environment;

    /// A nul inside a client variable must not smuggle in another variable
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
