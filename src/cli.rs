//! Administrative command-line handling.

use clap::{ArgGroup, CommandFactory, Parser, error::ErrorKind};
use std::ffi::OsString;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Compiler(Vec<OsString>),
    Explain { arguments: Vec<OsString>, json: bool },
    ShowStats { json: bool },
    ZeroStats,
    ShowConfig,
    Trim,
    Clear,
    Version,
    Help,
}

#[derive(Debug, Parser)]
#[command(
    name = "fcache",
    disable_help_flag = true,
    disable_version_flag = true,
    group(
        ArgGroup::new("action")
            .required(true)
            .multiple(false)
            .args([
                "explain",
                "show_stats",
                "zero_stats",
                "show_config",
                "trim",
                "clear",
                "version",
                "help",
            ])
    )
)]
struct Admin {
    #[arg(long)]
    explain: bool,
    #[arg(long = "show-stats")]
    show_stats: bool,
    #[arg(long)]
    json: bool,
    #[arg(long = "zero-stats")]
    zero_stats: bool,
    #[arg(long = "show-config")]
    show_config: bool,
    #[arg(long)]
    trim: bool,
    #[arg(long)]
    clear: bool,
    #[arg(long)]
    version: bool,
    #[arg(long)]
    help: bool,
    #[arg(last = true, requires = "explain", value_name = "COMPILER_AND_ARGUMENTS")]
    arguments: Vec<OsString>,
}

/// Parses a leading administrative option or returns a compiler argument vector unchanged.
pub fn parse<I>(args: I) -> Result<Command, clap::Error>
where
    I: IntoIterator<Item = OsString>,
{
    let args: Vec<OsString> = args.into_iter().collect();
    if !args.first().is_some_and(|arg| arg.to_str().is_some_and(|text| text.starts_with('-'))) {
        return Ok(Command::Compiler(args));
    }

    let admin = Admin::try_parse_from(
        std::iter::once(OsString::from("fcache")).chain(args.iter().cloned()),
    )?;

    if admin.json && !admin.show_stats && !admin.explain {
        return Err(Admin::command().error(
            ErrorKind::ArgumentConflict,
            "--json can only be used with --show-stats or --explain",
        ));
    }
    if admin.explain && admin.arguments.is_empty() {
        return Err(Admin::command().error(
            ErrorKind::MissingRequiredArgument,
            "--explain requires `-- <compiler> <arguments...>`",
        ));
    }

    Ok(if admin.explain {
        Command::Explain { arguments: admin.arguments, json: admin.json }
    } else if admin.show_stats {
        Command::ShowStats { json: admin.json }
    } else if admin.zero_stats {
        Command::ZeroStats
    } else if admin.show_config {
        Command::ShowConfig
    } else if admin.trim {
        Command::Trim
    } else if admin.clear {
        Command::Clear
    } else if admin.version {
        Command::Version
    } else {
        Command::Help
    })
}

pub fn parse_env() -> Result<Command, clap::Error> {
    parse(std::env::args_os().skip(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn compiler_arguments_are_preserved_verbatim() {
        let input = args(&["gfortran", "-O2", "--help", "--show-stats", "--json"]);
        assert_eq!(parse(input.clone()).unwrap(), Command::Compiler(input));
    }

    #[test]
    fn empty_invocation_remains_a_compiler_invocation() {
        assert_eq!(parse(Vec::new()).unwrap(), Command::Compiler(Vec::new()));
    }

    #[test]
    fn parses_all_administrative_actions() {
        assert_eq!(
            parse(args(&["--show-stats", "--json"])).unwrap(),
            Command::ShowStats { json: true }
        );
        assert_eq!(parse(args(&["--zero-stats"])).unwrap(), Command::ZeroStats);
        assert_eq!(parse(args(&["--show-config"])).unwrap(), Command::ShowConfig);
        assert_eq!(parse(args(&["--trim"])).unwrap(), Command::Trim);
        assert_eq!(parse(args(&["--clear"])).unwrap(), Command::Clear);
        assert_eq!(parse(args(&["--version"])).unwrap(), Command::Version);
        assert_eq!(parse(args(&["--help"])).unwrap(), Command::Help);
    }

    #[test]
    fn parses_explain_with_required_separator() {
        assert_eq!(
            parse(args(&["--explain", "--json", "--", "gfortran", "-c", "source.f90"])).unwrap(),
            Command::Explain { arguments: args(&["gfortran", "-c", "source.f90"]), json: true }
        );
    }

    #[test]
    fn administrative_actions_are_mutually_exclusive() {
        let error = parse(args(&["--trim", "--clear"])).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::ArgumentConflict);
    }

    #[test]
    fn unsupported_json_is_an_error() {
        let error = parse(args(&["--zero-stats", "--json"])).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::ArgumentConflict);
        assert!(error.to_string().contains("--show-stats or --explain"));
    }

    #[test]
    fn json_without_an_action_is_an_error() {
        let error = parse(args(&["--json"])).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn explain_requires_a_compiler_command() {
        let error = parse(args(&["--explain"])).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::MissingRequiredArgument);
        assert!(error.to_string().contains("-- <compiler> <arguments...>"));
    }

    #[test]
    fn explain_rejects_arguments_without_separator() {
        let error = parse(args(&["--explain", "gfortran", "-c", "source.f90"])).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::UnknownArgument);
    }

    #[test]
    fn malformed_leading_option_is_not_a_compiler_invocation() {
        let error = parse(args(&["--show-stats=unexpected"])).unwrap_err();
        assert_ne!(error.kind(), ErrorKind::MissingRequiredArgument);
    }
}
