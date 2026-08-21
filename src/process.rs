//! Child compiler process execution.

use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

/// A command and the process settings used to execute it.
#[derive(Debug, Clone)]
pub struct CompilerCommand {
    program: OsString,
    args: Vec<OsString>,
    current_dir: Option<PathBuf>,
    environment: Option<Vec<(OsString, OsString)>>,
    tee_output: bool,
}

impl CompilerCommand {
    pub fn new(program: impl Into<OsString>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            current_dir: None,
            environment: None,
            tee_output: false,
        }
    }

    pub fn arg(mut self, arg: impl Into<OsString>) -> Self {
        self.args.push(arg.into());
        self
    }

    pub fn args<I, A>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = A>,
        A: Into<OsString>,
    {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    pub fn current_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.current_dir = Some(path.into());
        self
    }

    /// Set the complete child environment. No ambient variables are inherited.
    pub fn environment<I, K, V>(mut self, environment: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<OsString>,
        V: Into<OsString>,
    {
        self.environment =
            Some(environment.into_iter().map(|(key, value)| (key.into(), value.into())).collect());
        self
    }

    pub fn tee_output(mut self, tee: bool) -> Self {
        self.tee_output = tee;
        self
    }

    pub fn run(self) -> Result<CompilerOutput, ProcessError> {
        run_compiler(self)
    }
}

/// Captured output and completion details for a compiler invocation.
#[derive(Debug)]
pub struct CompilerOutput {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub elapsed: Duration,
}

#[derive(Debug, thiserror::Error)]
pub enum ProcessError {
    #[error("failed to spawn compiler: {0}")]
    Spawn(#[source] io::Error),
    #[error("failed waiting for compiler: {0}")]
    Wait(#[source] io::Error),
    #[error("failed reading compiler {stream}: {source}")]
    Read {
        stream: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("failed writing compiler {stream} to parent: {source}")]
    TeeWrite {
        stream: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("compiler output reader thread panicked")]
    ReaderPanic,
    #[error("compiler {0} pipe was not available")]
    MissingPipe(&'static str),
}

pub fn run_compiler(command: CompilerCommand) -> Result<CompilerOutput, ProcessError> {
    let started = Instant::now();
    let mut process = Command::new(&command.program);
    process
        .args(&command.args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(path) = command.current_dir {
        process.current_dir(path);
    }
    if let Some(environment) = command.environment {
        process.env_clear().envs(environment);
    }
    let mut child = process.spawn().map_err(ProcessError::Spawn)?;
    let stdout = child.stdout.take().ok_or(ProcessError::MissingPipe("stdout"))?;
    let stderr = child.stderr.take().ok_or(ProcessError::MissingPipe("stderr"))?;
    let tee = command.tee_output;
    let out_thread = thread::spawn(move || drain(stdout, "stdout", tee));
    let err_thread = thread::spawn(move || drain(stderr, "stderr", tee));
    let status = child.wait().map_err(ProcessError::Wait)?;
    let stdout = join_reader(out_thread)?;
    let stderr = join_reader(err_thread)?;
    Ok(CompilerOutput { status, stdout, stderr, elapsed: started.elapsed() })
}

fn drain<R: Read>(mut reader: R, stream: &'static str, tee: bool) -> Result<Vec<u8>, ProcessError> {
    let mut captured = Vec::new();
    let mut chunk = [0_u8; 16 * 1024];
    loop {
        let count =
            reader.read(&mut chunk).map_err(|source| ProcessError::Read { stream, source })?;
        if count == 0 {
            return Ok(captured);
        }
        captured.extend_from_slice(&chunk[..count]);
        if tee {
            let result = if stream == "stdout" {
                io::stdout().write_all(&chunk[..count])
            } else {
                io::stderr().write_all(&chunk[..count])
            };
            result.map_err(|source| ProcessError::TeeWrite { stream, source })?;
        }
    }
}

fn join_reader(
    handle: thread::JoinHandle<Result<Vec<u8>, ProcessError>>,
) -> Result<Vec<u8>, ProcessError> {
    handle.join().map_err(|_| ProcessError::ReaderPanic)?
}

/// Replace this process with a compiler, preserving the terminal and signals on Unix.
pub fn exec_compiler(command: CompilerCommand) -> Result<ExitStatus, ProcessError> {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let mut process = Command::new(&command.program);
        process
            .args(&command.args)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
        if let Some(path) = command.current_dir {
            process.current_dir(path);
        }
        if let Some(environment) = command.environment {
            process.env_clear().envs(environment);
        }
        Err(ProcessError::Spawn(process.exec()))
    }
    #[cfg(not(unix))]
    {
        let mut process = Command::new(&command.program);
        process
            .args(&command.args)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
        if let Some(path) = command.current_dir {
            process.current_dir(path);
        }
        if let Some(environment) = command.environment {
            process.env_clear().envs(environment);
        }
        process.spawn().map_err(ProcessError::Spawn)?.wait().map_err(ProcessError::Wait)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn captures_separate_streams_and_nonzero_status() {
        let result = CompilerCommand::new("/bin/sh")
            .args(["-c", "printf out; printf err >&2; exit 7"])
            .run()
            .unwrap();
        assert_eq!(result.stdout, b"out");
        assert_eq!(result.stderr, b"err");
        assert_eq!(result.status.code(), Some(7));
    }

    #[cfg(unix)]
    #[test]
    fn drains_large_simultaneous_output() {
        let result = CompilerCommand::new("/bin/sh")
            .args([
                "-c",
                "i=0; while [ $i -lt 20000 ]; do printf x; printf y >&2; i=$((i+1)); done",
            ])
            .run()
            .unwrap();
        assert_eq!(result.stdout.len(), 20_000);
        assert_eq!(result.stderr.len(), 20_000);
    }
}
