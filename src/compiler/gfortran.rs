//! gfortran invocation parsing and observation.

use std::ffi::{OsStr, OsString};
use std::path::Path;

use thiserror::Error;

#[path = "resolution.rs"]
pub mod resolution;

pub use resolution::{ForcedInput, ForcedInputKind, SearchPath, SearchPathKind};

/// Whether an invocation is eligible for caching.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Cacheability {
    Cacheable,
    Bypass(BypassReason),
}

/// A reason an invocation cannot safely be cached or probed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BypassReason {
    EmptyInvocation,
    ResponseFile(OsString),
    StdinSource,
    MissingSource,
    MultipleSources,
    NonFortranInput(OsString),
    LinkAction,
    PreprocessOnly,
    AssemblyOutput,
    StdoutDepfile,
    SaveTemps,
    DumpOutput,
    CoverageOrProfile,
    OptimizationRecord,
    FileDiagnostic,
    AutoFdo,
    LanguageOverride,
    ArgumentCarrier,
    PluginOrSpecs,
    UnknownOption(OsString),
    MissingDependencyProbePreprocessing,
    DuplicateModuleDirectory,
}

/// Preprocessing selected for a source file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Preprocessing {
    Auto,
    Cpp,
    NoCpp,
    Fpreprocessed,
}

impl Preprocessing {
    /// Whether an invocation can attempt a dependency probe.
    pub fn permits_probe(self) -> bool {
        matches!(self, Self::Auto | Self::Cpp)
    }
}

/// Dependency-file mode requested for the real compiler invocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DependencyMode {
    /// Include user and system prerequisites.
    Md,
    /// Omit system prerequisites from the user depfile.
    Mmd,
}

/// Parsed gfortran command-line state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GfortranInvocation {
    pub cacheability: Cacheability,
    pub source: Option<OsString>,
    pub object: Option<OsString>,
    pub module_dir: Option<OsString>,
    pub include_dirs: Vec<OsString>,
    pub original_module_dirs: Vec<OsString>,
    /// Ordered command-line search paths, classified by compiler search tier.
    pub search_paths: Vec<SearchPath>,
    /// Files injected into preprocessing with `-include` or `-imacros`.
    pub forced_inputs: Vec<ForcedInput>,
    /// Command-line intrinsic module search directories.
    pub intrinsic_module_dirs: Vec<OsString>,
    pub user_depfile: Option<OsString>,
    pub dependency_mode: Option<DependencyMode>,
    pub dependency_target_modifiers: Vec<OsString>,
    pub compile_only: bool,
    pub syntax_only: bool,
    pub preprocessing: Preprocessing,
    pub original_args: Vec<OsString>,
    extra_args: Vec<OsString>,
    unmodeled_search_argument: Option<OsString>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ParseError {
    #[error("gfortran argument list is empty")]
    EmptyInvocation,
    #[error("option {option:?} requires an argument")]
    MissingOptionArgument { option: OsString },
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProbeError {
    #[error("invocation is not probeable: {0:?}")]
    NotProbeable(BypassReason),
    #[error("dependency probe internal path is empty")]
    EmptyInternalPath,
    #[error("dependency probe module path is empty")]
    EmptyPrivateModulePath,
}

/// Parse argv after the compiler executable.
pub fn parse_args(args: &[OsString]) -> Result<GfortranInvocation, ParseError> {
    if args.is_empty() {
        return Err(ParseError::EmptyInvocation);
    }
    let mut invocation = GfortranInvocation {
        cacheability: Cacheability::Cacheable,
        source: None,
        object: None,
        module_dir: None,
        include_dirs: Vec::new(),
        original_module_dirs: Vec::new(),
        search_paths: Vec::new(),
        forced_inputs: Vec::new(),
        intrinsic_module_dirs: Vec::new(),
        user_depfile: None,
        dependency_mode: None,
        dependency_target_modifiers: Vec::new(),
        compile_only: false,
        syntax_only: false,
        preprocessing: Preprocessing::Auto,
        original_args: args.to_vec(),
        extra_args: Vec::new(),
        unmodeled_search_argument: None,
    };
    let mut positional = Vec::new();
    let mut index = 0;
    let mut end_options = false;
    let mut explicit_cpp = None;
    let mut fpreprocessed = false;
    while index < args.len() {
        let arg = &args[index];
        let bytes = encoded(arg);
        if !end_options && arg == OsStr::new("--") {
            end_options = true;
            index += 1;
            continue;
        }
        if !end_options && bytes.first() == Some(&b'@') {
            mark_bypass(&mut invocation, BypassReason::ResponseFile(arg.clone()));
            index += 1;
            continue;
        }
        if !end_options && arg == OsStr::new("-c") {
            invocation.compile_only = true;
            index += 1;
            continue;
        }
        if !end_options && arg == OsStr::new("-fsyntax-only") {
            invocation.syntax_only = true;
            index += 1;
            continue;
        }
        if !end_options && arg == OsStr::new("-cpp") {
            explicit_cpp = Some(true);
            index += 1;
            continue;
        }
        if !end_options && arg == OsStr::new("-nocpp") {
            explicit_cpp = Some(false);
            index += 1;
            continue;
        }
        if !end_options && arg == OsStr::new("-fpreprocessed") {
            fpreprocessed = true;
            index += 1;
            continue;
        }
        if !end_options && (arg == OsStr::new("-MD") || arg == OsStr::new("-MMD")) {
            invocation.dependency_mode = Some(if arg == OsStr::new("-MD") {
                DependencyMode::Md
            } else {
                DependencyMode::Mmd
            });
            index += 1;
            continue;
        }
        if !end_options && arg == OsStr::new("-MP") {
            invocation.dependency_target_modifiers.push(arg.clone());
            index += 1;
            continue;
        }
        if !end_options && arg == OsStr::new("-MG") {
            index += 1;
            continue;
        }
        if !end_options && (arg == OsStr::new("-MT") || arg == OsStr::new("-MQ")) {
            let value = next_value(args, index, arg)?;
            invocation.dependency_target_modifiers.push(arg.clone());
            invocation.dependency_target_modifiers.push(value);
            index += 2;
            continue;
        }
        if !end_options && (bytes.starts_with(b"-MT") || bytes.starts_with(b"-MQ")) {
            if bytes.len() == 3 {
                return Err(ParseError::MissingOptionArgument { option: arg.clone() });
            }
            invocation.dependency_target_modifiers.push(arg.clone());
            index += 1;
            continue;
        }
        if !end_options && (arg == OsStr::new("-M") || arg == OsStr::new("-MM")) {
            mark_bypass(&mut invocation, BypassReason::PreprocessOnly);
            index += 1;
            continue;
        }
        if !end_options && (arg == OsStr::new("-E") || arg == OsStr::new("-S")) {
            mark_bypass(
                &mut invocation,
                if arg == OsStr::new("-E") {
                    BypassReason::PreprocessOnly
                } else {
                    BypassReason::AssemblyOutput
                },
            );
            index += 1;
            continue;
        }
        if !end_options
            && (arg == OsStr::new("-o")
                || arg == OsStr::new("-J")
                || arg == OsStr::new("-I")
                || arg == OsStr::new("-MF"))
        {
            let value = next_value(args, index, arg)?;
            match arg.to_string_lossy().as_ref() {
                "-o" => invocation.object = Some(value),
                "-J" => {
                    invocation.original_module_dirs.push(value);
                }
                "-I" => {
                    if value == OsStr::new("-") {
                        invocation.unmodeled_search_argument = Some(arg.clone());
                    }
                    invocation.include_dirs.push(value.clone());
                    invocation
                        .search_paths
                        .push(SearchPath { kind: SearchPathKind::Include, path: value.clone() });
                    invocation.extra_args.push(OsString::from("-I"));
                    invocation.extra_args.push(value);
                }
                "-MF" => {
                    if value == OsStr::new("-") {
                        mark_bypass(&mut invocation, BypassReason::StdoutDepfile);
                    }
                    invocation.user_depfile = Some(value);
                }
                _ => unreachable!(),
            }
            index += 2;
            continue;
        }
        if !end_options
            && (bytes.starts_with(b"-o")
                || bytes.starts_with(b"-J")
                || bytes.starts_with(b"-I")
                || bytes.starts_with(b"-MF"))
        {
            let (prefix, value): (&[u8], &[u8]) = if bytes.starts_with(b"-MF") {
                (b"-MF", &bytes[3..])
            } else if bytes.starts_with(b"-J") {
                (b"-J", &bytes[2..])
            } else if bytes.starts_with(b"-I") {
                (b"-I", &bytes[2..])
            } else {
                (b"-o", &bytes[2..])
            };
            if value.is_empty() {
                return Err(ParseError::MissingOptionArgument { option: arg.clone() });
            }
            let value = os_value(value);
            match prefix {
                b"-MF" => {
                    if value == OsStr::new("-") {
                        mark_bypass(&mut invocation, BypassReason::StdoutDepfile);
                    }
                    invocation.user_depfile = Some(value);
                }
                b"-J" => {
                    invocation.original_module_dirs.push(value);
                }
                b"-I" => {
                    if value == OsStr::new("-") {
                        invocation.unmodeled_search_argument = Some(arg.clone());
                    }
                    invocation.include_dirs.push(value.clone());
                    invocation
                        .search_paths
                        .push(SearchPath { kind: SearchPathKind::Include, path: value.clone() });
                    invocation.extra_args.push(OsString::from("-I"));
                    invocation.extra_args.push(value);
                }
                _ => invocation.object = Some(value),
            }
            index += 1;
            continue;
        }
        if !end_options && bytes == b"-x" {
            let _ = next_value(args, index, arg)?;
            mark_bypass(&mut invocation, BypassReason::LanguageOverride);
            index += 2;
            continue;
        }
        if !end_options && is_safe_argument_carrier(&bytes) {
            invocation.extra_args.push(arg.clone());
            index += 1;
            continue;
        }
        if !end_options && is_separate_argument_carrier(&bytes) {
            let _ = next_value(args, index, arg)?;
            mark_bypass(&mut invocation, BypassReason::ArgumentCarrier);
            index += 2;
            continue;
        }
        if !end_options && is_separate_value_option(&bytes) {
            let value = next_value(args, index, arg)?;
            record_resolution_option(&mut invocation, &bytes, &value);
            invocation.extra_args.push(arg.clone());
            invocation.extra_args.push(value);
            index += 2;
            continue;
        }
        if !end_options && is_rejected_side_effect(&bytes) {
            mark_bypass(&mut invocation, side_effect_reason(&bytes));
            index += 1;
            continue;
        }
        if !end_options && bytes.starts_with(b"-") {
            if is_safe_option(&bytes) {
                record_attached_resolution_option(&mut invocation, arg, &bytes);
                invocation.extra_args.push(arg.clone());
                index += 1;
                continue;
            }
            mark_bypass(&mut invocation, BypassReason::UnknownOption(arg.clone()));
            index += 1;
            continue;
        }
        positional.push(arg.clone());
        index += 1;
    }

    if invocation.original_module_dirs.len() > 1 {
        invocation.module_dir = None;
        mark_bypass(&mut invocation, BypassReason::DuplicateModuleDirectory);
    } else {
        invocation.module_dir = invocation.original_module_dirs.first().cloned();
    }

    for value in positional {
        if value == OsStr::new("-") {
            mark_bypass(&mut invocation, BypassReason::StdinSource);
        } else if is_fortran_source(&value) {
            if invocation.source.is_some() {
                mark_bypass(&mut invocation, BypassReason::MultipleSources);
            } else {
                invocation.source = Some(value);
            }
        } else {
            mark_bypass(&mut invocation, BypassReason::NonFortranInput(value));
        }
    }
    if invocation.source.is_none() {
        mark_bypass(&mut invocation, BypassReason::MissingSource);
    }
    if !invocation.compile_only && !invocation.syntax_only {
        mark_bypass(&mut invocation, BypassReason::LinkAction);
    }
    let auto_cpp =
        invocation.source.as_ref().is_some_and(|source| has_uppercase_fortran_extension(source));
    invocation.preprocessing = if fpreprocessed {
        Preprocessing::Fpreprocessed
    } else if let Some(cpp) = explicit_cpp {
        if cpp { Preprocessing::Cpp } else { Preprocessing::NoCpp }
    } else if auto_cpp {
        Preprocessing::Cpp
    } else {
        Preprocessing::Auto
    };
    if invocation.dependency_mode.is_some() && invocation.user_depfile.is_none() {
        invocation.user_depfile = default_depfile(&invocation);
    }
    Ok(invocation)
}

/// Alias for callers that use the adapter name.
pub fn parse_gfortran_args(args: &[OsString]) -> Result<GfortranInvocation, ParseError> {
    parse_args(args)
}

impl GfortranInvocation {
    /// Construct a preprocessing qualification invocation for an automatic lowercase source.
    pub fn preprocessor_identity_argv(&self) -> Result<Vec<OsString>, ProbeError> {
        self.preprocessor_probe_argv(Preprocessing::Auto)
    }

    /// Construct a preprocessing observation invocation for legacy gfortran versions.
    pub fn preprocessor_observation_argv(&self) -> Result<Vec<OsString>, ProbeError> {
        self.preprocessor_probe_argv(Preprocessing::Cpp)
    }

    fn preprocessor_probe_argv(
        &self,
        preprocessing: Preprocessing,
    ) -> Result<Vec<OsString>, ProbeError> {
        if let Cacheability::Bypass(reason) = &self.cacheability {
            return Err(ProbeError::NotProbeable(reason.clone()));
        }
        if self.preprocessing != preprocessing {
            return Err(ProbeError::NotProbeable(
                BypassReason::MissingDependencyProbePreprocessing,
            ));
        }
        let Some(source) = &self.source else {
            return Err(ProbeError::NotProbeable(BypassReason::MissingSource));
        };
        let mut probe = self.extra_args.clone();
        self.push_original_module_search(&mut probe);
        probe.extend([
            OsString::from("-cpp"),
            OsString::from("-Werror=date-time"),
            OsString::from("-E"),
            OsString::from("-P"),
            source.clone(),
        ]);
        Ok(probe)
    }

    /// Construct a private dependency probe invocation.
    pub fn dependency_probe_argv(
        &self,
        internal_depfile: &OsStr,
        private_module_dir: &OsStr,
    ) -> Result<Vec<OsString>, ProbeError> {
        if internal_depfile.is_empty() {
            return Err(ProbeError::EmptyInternalPath);
        }
        if private_module_dir.is_empty() {
            return Err(ProbeError::EmptyPrivateModulePath);
        }
        if let Cacheability::Bypass(reason) = &self.cacheability {
            return Err(ProbeError::NotProbeable(reason.clone()));
        }
        if !self.preprocessing.permits_probe() {
            return Err(ProbeError::NotProbeable(
                BypassReason::MissingDependencyProbePreprocessing,
            ));
        }
        let Some(source) = &self.source else {
            return Err(ProbeError::NotProbeable(BypassReason::MissingSource));
        };
        let mut probe = self.extra_args.clone();
        self.push_original_module_search(&mut probe);
        probe.extend([
            OsString::from("-fsyntax-only"),
            OsString::from("-cpp"),
            OsString::from("-Werror=date-time"),
            OsString::from("-MD"),
            OsString::from("-MF"),
            internal_depfile.to_os_string(),
            OsString::from("-J"),
            private_module_dir.to_os_string(),
        ]);
        probe.extend(self.dependency_target_modifiers.iter().cloned());
        if let Some(object) = &self.object {
            probe.push(OsString::from("-o"));
            probe.push(object.clone());
        }
        probe.push(source.clone());
        Ok(probe)
    }

    fn push_original_module_search(&self, argv: &mut Vec<OsString>) {
        if let [directory] = self.original_module_dirs.as_slice() {
            argv.push(OsString::from("-I"));
            argv.push(directory.clone());
        }
    }
}

fn default_depfile(invocation: &GfortranInvocation) -> Option<OsString> {
    if let Some(object) = &invocation.object {
        return Some(Path::new(object).with_extension("d").into_os_string());
    }
    let source = invocation.source.as_ref()?;
    let file_name = Path::new(source).file_name()?;
    Some(Path::new(file_name).with_extension("d").into_os_string())
}

fn next_value(args: &[OsString], index: usize, option: &OsStr) -> Result<OsString, ParseError> {
    args.get(index + 1)
        .cloned()
        .ok_or_else(|| ParseError::MissingOptionArgument { option: option.to_os_string() })
}

fn mark_bypass(invocation: &mut GfortranInvocation, reason: BypassReason) {
    if matches!(invocation.cacheability, Cacheability::Cacheable) {
        invocation.cacheability = Cacheability::Bypass(reason);
    }
}

fn record_resolution_option(invocation: &mut GfortranInvocation, option: &[u8], value: &OsStr) {
    let search_kind = match option {
        b"-iquote" => Some(SearchPathKind::Quote),
        b"-isystem" => Some(SearchPathKind::System),
        b"-idirafter" => Some(SearchPathKind::After),
        _ => None,
    };
    if let Some(kind) = search_kind {
        invocation.search_paths.push(SearchPath { kind, path: value.to_os_string() });
        return;
    }
    let forced_kind = match option {
        b"-include" => Some(ForcedInputKind::Include),
        b"-imacros" => Some(ForcedInputKind::Imacros),
        _ => None,
    };
    if let Some(kind) = forced_kind {
        invocation.forced_inputs.push(ForcedInput { kind, path: value.to_os_string() });
        return;
    }
    if option == b"-fintrinsic-modules-path" {
        invocation.intrinsic_module_dirs.push(value.to_os_string());
        return;
    }
    if matches!(option, b"-iframework" | b"-F") {
        invocation.unmodeled_search_argument = Some(os_value(option));
    }
}

fn record_attached_resolution_option(
    invocation: &mut GfortranInvocation,
    argument: &OsStr,
    bytes: &[u8],
) {
    for (prefix, kind) in [
        (b"-iquote".as_slice(), SearchPathKind::Quote),
        (b"-isystem".as_slice(), SearchPathKind::System),
        (b"-idirafter".as_slice(), SearchPathKind::After),
    ] {
        if let Some(value) = bytes.strip_prefix(prefix).filter(|value| !value.is_empty()) {
            if value.first() == Some(&b'-') {
                invocation.unmodeled_search_argument = Some(argument.to_os_string());
            } else {
                invocation.search_paths.push(SearchPath { kind, path: os_value(value) });
            }
            return;
        }
    }
    for (prefix, kind) in [
        (b"-include".as_slice(), ForcedInputKind::Include),
        (b"-imacros".as_slice(), ForcedInputKind::Imacros),
    ] {
        if let Some(value) = bytes.strip_prefix(prefix).filter(|value| !value.is_empty()) {
            if value.first() == Some(&b'-') {
                invocation.unmodeled_search_argument = Some(argument.to_os_string());
            } else {
                invocation.forced_inputs.push(ForcedInput { kind, path: os_value(value) });
            }
            return;
        }
    }
    if let Some(value) = bytes.strip_prefix(b"-fintrinsic-modules-path=") {
        invocation.intrinsic_module_dirs.push(os_value(value));
    } else if bytes.starts_with(b"-F") {
        invocation.unmodeled_search_argument = Some(argument.to_os_string());
    }
}

fn is_rejected_side_effect(arg: &[u8]) -> bool {
    is_language_override(arg)
        || is_argument_carrier(arg)
        || arg == b"--coverage"
        || arg == b"-coverage"
        || arg == b"-p"
        || arg == b"-pg"
        || arg == b"-fprofile-arcs"
        || arg == b"-ftest-coverage"
        || arg == b"-fcondition-coverage"
        || arg == b"-fpath-coverage"
        || arg == b"-fbranch-probabilities"
        || arg.starts_with(b"-fprofile-")
        || arg.starts_with(b"-fauto-profile")
        || arg.starts_with(b"-fprofile-sample-use")
        || arg.starts_with(b"-save-temps")
        || arg.starts_with(b"-dump")
        || arg.starts_with(b"-fdump-")
        || arg.starts_with(b"-fopt-info")
        || arg.starts_with(b"-fsave-optimization-record")
        || arg.starts_with(b"-foptimization-record-file")
        || is_file_diagnostic(arg)
        || arg.starts_with(b"-ftime-report")
        || arg.starts_with(b"-fmem-report")
        || arg.starts_with(b"-fstack-usage")
        || arg.starts_with(b"-fcallgraph-info")
        || arg.starts_with(b"-fplugin")
        || arg.starts_with(b"-specs")
}

fn side_effect_reason(arg: &[u8]) -> BypassReason {
    if is_language_override(arg) {
        BypassReason::LanguageOverride
    } else if is_argument_carrier(arg) {
        BypassReason::ArgumentCarrier
    } else if arg.starts_with(b"-fauto-profile") || arg.starts_with(b"-fprofile-sample-use") {
        BypassReason::AutoFdo
    } else if arg.starts_with(b"-fsave-optimization-record")
        || arg.starts_with(b"-foptimization-record-file")
    {
        BypassReason::OptimizationRecord
    } else if is_file_diagnostic(arg) {
        BypassReason::FileDiagnostic
    } else if arg.starts_with(b"-save-temps") {
        BypassReason::SaveTemps
    } else if arg.starts_with(b"-dump")
        || arg.starts_with(b"-fdump-")
        || arg.starts_with(b"-fopt-info")
        || arg.starts_with(b"-ftime-report")
        || arg.starts_with(b"-fmem-report")
        || arg.starts_with(b"-fstack-usage")
        || arg.starts_with(b"-fcallgraph-info")
    {
        BypassReason::DumpOutput
    } else if arg.starts_with(b"-fplugin") || arg.starts_with(b"-specs") {
        BypassReason::PluginOrSpecs
    } else {
        BypassReason::CoverageOrProfile
    }
}

fn is_language_override(arg: &[u8]) -> bool {
    arg.starts_with(b"-x")
}

fn is_separate_argument_carrier(arg: &[u8]) -> bool {
    matches!(arg, b"-Wp" | b"-Wa" | b"-Wl" | b"-Xpreprocessor" | b"-Xassembler" | b"-Xlinker")
}

fn is_argument_carrier(arg: &[u8]) -> bool {
    arg.starts_with(b"-Wp,")
        || arg.starts_with(b"-Wa,")
        || arg.starts_with(b"-Wl,")
        || arg.starts_with(b"-Xpreprocessor=")
        || arg.starts_with(b"-Xassembler=")
        || arg.starts_with(b"-Xlinker=")
}

fn is_safe_argument_carrier(arg: &[u8]) -> bool {
    arg == b"-Wa,--noexecstack"
}

fn is_file_diagnostic(arg: &[u8]) -> bool {
    arg.starts_with(b"-fdiagnostics-file=")
        || arg.starts_with(b"-fdiagnostics-add-output=")
        || arg.starts_with(b"-fdiagnostics-set-output=")
        || arg.starts_with(b"-fdiagnostics-format=sarif")
}

fn is_separate_value_option(arg: &[u8]) -> bool {
    matches!(
        arg,
        b"-D"
            | b"-U"
            | b"-include"
            | b"-imacros"
            | b"-isystem"
            | b"-isysroot"
            | b"-iframework"
            | b"-iquote"
            | b"-idirafter"
            | b"-F"
            | b"-fintrinsic-modules-path"
    )
}

fn is_safe_option(arg: &[u8]) -> bool {
    is_safe_optimization_option(arg)
        || is_safe_warning_option(arg)
        || is_safe_fortran_option(arg)
        || is_safe_machine_option(arg)
        || is_safe_debug_option(arg)
        || matches!(
            arg,
            b"-pedantic" | b"-pedantic-errors" | b"-traditional-cpp" | b"-undef" | b"-P"
        )
        || matches!(
            arg,
            b"-std=f95"
                | b"-std=f2003"
                | b"-std=f2008"
                | b"-std=f2008ts"
                | b"-std=f2018"
                | b"-std=f2023"
                | b"-std=gnu"
                | b"-std=legacy"
        )
        || arg.starts_with(b"-D")
        || arg.starts_with(b"-U")
        || arg.starts_with(b"-include")
        || arg.starts_with(b"-imacros")
        || arg.starts_with(b"-isystem")
        || arg.starts_with(b"-iquote")
        || arg.starts_with(b"-idirafter")
        || has_value_prefix(arg, &[b"-F"])
        || is_safe_instrumentation_option(arg)
}

fn is_safe_optimization_option(arg: &[u8]) -> bool {
    matches!(arg, b"-O" | b"-O0" | b"-O1" | b"-O2" | b"-O3" | b"-Os" | b"-Og" | b"-Ofast" | b"-Oz")
}

fn is_safe_warning_option(arg: &[u8]) -> bool {
    matches!(
        arg,
        b"-w"
            | b"-Wall"
            | b"-Wextra"
            | b"-Werror"
            | b"-Wpedantic"
            | b"-Wconversion"
            | b"-Wconversion-extra"
            | b"-Wimplicit-interface"
            | b"-Wimplicit-procedure"
            | b"-Winteger-division"
            | b"-Wintrinsic-shadow"
            | b"-Wintrinsics-std"
            | b"-Wline-truncation"
            | b"-Wreal-q-constant"
            | b"-Wsurprising"
            | b"-Wunderflow"
            | b"-Warray-temporaries"
            | b"-Wcharacter-truncation"
            | b"-Wfunction-elimination"
            | b"-Wrealloc-lhs"
            | b"-Wrealloc-lhs-all"
            | b"-Wcompare-reals"
            | b"-Wtarget-lifetime"
            | b"-Wdo-subscript"
            | b"-Wuse-without-only"
            | b"-Wno-align-commons"
            | b"-Wno-aliasing"
            | b"-Wno-c-binding-type"
            | b"-Wno-conversion"
            | b"-Wno-unused-dummy-argument"
            | b"-Wmaybe-uninitialized"
    )
}

fn is_safe_fortran_option(arg: &[u8]) -> bool {
    matches!(
        arg,
        b"-fall-intrinsics"
            | b"-fbacktrace"
            | b"-fbackslash"
            | b"-fbounds-check"
            | b"-fcray-pointer"
            | b"-fd-lines-as-code"
            | b"-fd-lines-as-comments"
            | b"-fdefault-double-8"
            | b"-fdefault-integer-8"
            | b"-fdefault-real-8"
            | b"-fdollar-ok"
            | b"-ffixed-form"
            | b"-ffree-form"
            | b"-fimplicit-none"
            | b"-finteger-4-integer-8"
            | b"-fmodule-private"
            | b"-fno-align-commons"
            | b"-fno-backslash"
            | b"-fno-backtrace"
            | b"-fno-f2c"
            | b"-fno-range-check"
            | b"-fno-realloc-lhs"
            | b"-fno-second-underscore"
            | b"-fno-underscoring"
            | b"-frange-check"
            | b"-freal-4-real-8"
            | b"-freal-4-real-10"
            | b"-freal-4-real-16"
            | b"-freal-8-real-4"
            | b"-freal-8-real-10"
            | b"-freal-8-real-16"
            | b"-frecursive"
            | b"-frepack-arrays"
            | b"-fsecond-underscore"
            | b"-fstack-arrays"
            | b"-funderscoring"
            | b"-fwhole-file"
            | b"-fPIC"
            | b"-fpic"
            | b"-fPIE"
            | b"-fpie"
            | b"-fno-pic"
            | b"-fno-PIC"
            | b"-fno-pie"
            | b"-fno-PIE"
            | b"-fopenmp"
            | b"-fopenacc"
            | b"-flto"
            | b"-fno-lto"
            | b"-ffast-math"
            | b"-fno-fast-math"
            | b"-fdata-sections"
            | b"-ffunction-sections"
            | b"-funroll-loops"
            | b"-funroll-all-loops"
            | b"-fno-unroll-loops"
            | b"-ftree-vectorize"
            | b"-fno-tree-vectorize"
            | b"-fomit-frame-pointer"
            | b"-fno-omit-frame-pointer"
            | b"-fwrapv"
            | b"-fno-wrapv"
            | b"-fvisibility=hidden"
    ) || has_value_prefix(
        arg,
        &[
            b"-fblas-matmul-limit=",
            b"-fcheck=",
            b"-fcoarray=",
            b"-fconvert=",
            b"-ffpe-summary=",
            b"-ffile-prefix-map=",
            b"-ffixed-line-length-",
            b"-ffree-line-length-",
            b"-finline-limit=",
            b"-fintrinsic-modules-path=",
            b"-fmax-identifier-length=",
            b"-fmax-stack-var-size=",
            b"-fpack-derived=",
            b"-frecord-marker=",
            b"-frandom-seed=",
        ],
    )
}

fn is_safe_instrumentation_option(arg: &[u8]) -> bool {
    has_value_prefix(
        arg,
        &[b"-fsanitize=", b"-fno-sanitize=", b"-fsanitize-recover=", b"-fno-sanitize-recover="],
    )
}

fn is_safe_machine_option(arg: &[u8]) -> bool {
    matches!(arg, b"-m32" | b"-m64" | b"-mx32" | b"-msoft-float" | b"-mhard-float")
        || has_value_prefix(
            arg,
            &[b"-march=", b"-mcpu=", b"-mtune=", b"-mfpu=", b"-mabi=", b"-mmacosx-version-min="],
        )
}

fn is_safe_debug_option(arg: &[u8]) -> bool {
    matches!(
        arg,
        b"-g"
            | b"-g0"
            | b"-g1"
            | b"-g2"
            | b"-g3"
            | b"-ggdb"
            | b"-ggdb0"
            | b"-ggdb1"
            | b"-ggdb2"
            | b"-ggdb3"
            | b"-gdwarf"
            | b"-gdwarf-2"
            | b"-gdwarf-3"
            | b"-gdwarf-4"
            | b"-gdwarf-5"
    ) || has_value_prefix(arg, &[b"-fdebug-prefix-map=", b"-fmacro-prefix-map="])
}

fn has_value_prefix(arg: &[u8], prefixes: &[&[u8]]) -> bool {
    prefixes.iter().any(|prefix| arg.starts_with(prefix) && arg.len() > prefix.len())
}

fn encoded(value: &OsStr) -> Vec<u8> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        value.as_bytes().to_vec()
    }
    #[cfg(not(unix))]
    {
        value.to_string_lossy().as_bytes().to_vec()
    }
}

fn os_value(value: &[u8]) -> OsString {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        OsString::from_vec(value.to_vec())
    }
    #[cfg(not(unix))]
    {
        OsString::from(String::from_utf8_lossy(value).into_owned())
    }
}

fn is_fortran_source(value: &OsStr) -> bool {
    let Some(extension) = Path::new(value).extension() else {
        return false;
    };
    let extension = encoded(extension);
    matches!(
        extension.as_slice(),
        b"f" | b"for"
            | b"f77"
            | b"f90"
            | b"f95"
            | b"f03"
            | b"f08"
            | b"f18"
            | b"F"
            | b"FOR"
            | b"F77"
            | b"F90"
            | b"F95"
            | b"F03"
            | b"F08"
            | b"F18"
            | b"fpp"
            | b"FPP"
    )
}

fn has_uppercase_fortran_extension(value: &OsStr) -> bool {
    let Some(extension) = Path::new(value).extension() else {
        return false;
    };
    let extension = encoded(extension);
    extension.iter().any(u8::is_ascii_uppercase)
}

#[cfg(test)]
mod tests {
    use super::{
        BypassReason, Cacheability, DependencyMode, Preprocessing, ProbeError, parse_args,
    };
    use std::ffi::{OsStr, OsString};

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    fn assert_bypass(option_args: &[&str], expected: BypassReason) {
        let mut command = vec!["-c"];
        command.extend_from_slice(option_args);
        command.push("main.f90");
        assert_eq!(
            parse_args(&args(&command)).unwrap().cacheability,
            Cacheability::Bypass(expected)
        );
    }

    #[test]
    fn parses_ordered_paths_and_outputs() {
        let parsed = parse_args(&args(&[
            "-c",
            "-cpp",
            "-Ione",
            "-I",
            "two",
            "-Jold",
            "-o",
            "x.o",
            "-MMD",
            "-MFdeps.d",
            "main.f90",
        ]))
        .unwrap();
        assert_eq!(parsed.cacheability, Cacheability::Cacheable);
        assert_eq!(parsed.preprocessing, Preprocessing::Cpp);
        assert_eq!(parsed.include_dirs, args(&["one", "two"]));
        assert_eq!(parsed.original_module_dirs, args(&["old"]));
        assert_eq!(parsed.object, Some(OsString::from("x.o")));
        assert_eq!(parsed.user_depfile, Some(OsString::from("deps.d")));
        assert_eq!(parsed.dependency_mode, Some(DependencyMode::Mmd));
    }

    #[test]
    fn rejects_links_response_files_and_side_effects() {
        let linked = parse_args(&args(&["main.f90"])).unwrap();
        assert_eq!(linked.cacheability, Cacheability::Bypass(BypassReason::LinkAction));
        let response = parse_args(&args(&["-c", "@args", "main.f90"])).unwrap();
        assert!(matches!(
            response.cacheability,
            Cacheability::Bypass(BypassReason::ResponseFile(_))
        ));
        let profile = parse_args(&args(&["-c", "-fprofile-generate", "main.f90"])).unwrap();
        assert_eq!(profile.cacheability, Cacheability::Bypass(BypassReason::CoverageOrProfile));
        let callgraph = parse_args(&args(&["-c", "-fcallgraph-info", "main.f90"])).unwrap();
        assert_eq!(callgraph.cacheability, Cacheability::Bypass(BypassReason::DumpOutput));
    }

    #[test]
    fn accepts_explicitly_supported_semantic_options() {
        let parsed = parse_args(&args(&[
            "-c",
            "-Wall",
            "-Wimplicit-interface",
            "-O2",
            "-std=f2018",
            "-ffree-form",
            "-fcheck=bounds",
            "-fPIC",
            "-march=native",
            "-g3",
            "main.f90",
        ]))
        .unwrap();
        assert_eq!(parsed.cacheability, Cacheability::Cacheable);
    }

    #[test]
    fn accepts_wsjtx_macos_options() {
        let command = args(&[
            "-c",
            "-cpp",
            "-isysroot",
            "/Applications/Xcode.app/SDKs/MacOSX.sdk",
            "-iframework",
            "/opt/homebrew/opt/qt@5/lib",
            "-F/opt/homebrew/opt/qt@5/lib",
            "-mmacosx-version-min=12.0",
            "-fno-f2c",
            "-fbounds-check",
            "-fbacktrace",
            "-ffpe-summary=invalid,zero,overflow",
            "-Wmaybe-uninitialized",
            "-Wno-conversion",
            "-Wno-c-binding-type",
            "-Wno-aliasing",
            "-Wno-unused-dummy-argument",
            "-fno-second-underscore",
            "-fvisibility=hidden",
            "-O3",
            "-funroll-loops",
            "-funroll-all-loops",
            "-Wall",
            "-J",
            "modules",
            "-fopenmp",
            "main.F90",
        ]);
        let parsed = parse_args(&command).unwrap();
        assert_eq!(parsed.cacheability, Cacheability::Cacheable);
        assert_eq!(parsed.original_args, command);
    }

    #[test]
    fn accepts_wsjtx_linux_options() {
        let command = args(&[
            "-c",
            "-cpp",
            "-Wa,--noexecstack",
            "-fsanitize=address,undefined",
            "-fno-sanitize-recover=all",
            "-fno-omit-frame-pointer",
            "-fdata-sections",
            "-ffunction-sections",
            "main.F90",
        ]);
        let parsed = parse_args(&command).unwrap();
        assert_eq!(parsed.cacheability, Cacheability::Cacheable);
        assert_eq!(parsed.original_args, command);
    }

    #[test]
    fn rejects_missing_isysroot_value() {
        assert_eq!(
            parse_args(&args(&["-c", "main.F90", "-isysroot"])),
            Err(super::ParseError::MissingOptionArgument { option: OsString::from("-isysroot") })
        );
    }

    #[test]
    fn rejects_missing_framework_search_values() {
        for option in ["-iframework", "-F"] {
            assert_eq!(
                parse_args(&args(&["-c", "main.F90", option])),
                Err(super::ParseError::MissingOptionArgument { option: OsString::from(option) })
            );
        }
    }

    #[test]
    fn rejects_nearby_unsupported_wsjtx_option_spellings() {
        for option in [
            "-isysroot/Applications/Xcode.app/SDKs/MacOSX.sdk",
            "-mmacosx-version-min",
            "-mmacosx-version-min=",
            "-fno-f2cc",
            "-ffpe-summary=",
            "-ffpe-summaries=all",
            "-Wno-conversions",
            "-Wno-c-binding-types",
            "-fno-second-underscores",
            "-fvisibility=default",
        ] {
            assert_bypass(&[option], BypassReason::UnknownOption(OsString::from(option)));
        }
    }

    #[test]
    fn bypasses_language_overrides() {
        assert_bypass(&["-x", "f95"], BypassReason::LanguageOverride);
        assert_bypass(&["-xf95"], BypassReason::LanguageOverride);
        assert_bypass(&["-x=f95"], BypassReason::LanguageOverride);
    }

    #[test]
    fn bypasses_coverage_and_profile_outputs() {
        for option in [
            "--coverage",
            "-coverage",
            "-fprofile-arcs",
            "-ftest-coverage",
            "-fcondition-coverage",
            "-fpath-coverage",
            "-fprofile-generate",
            "-fprofile-use=profiles",
        ] {
            assert_bypass(&[option], BypassReason::CoverageOrProfile);
        }
    }

    #[test]
    fn bypasses_optimization_records() {
        assert_bypass(&["-fsave-optimization-record"], BypassReason::OptimizationRecord);
        assert_bypass(
            &["-foptimization-record-file=main.opt-record.json.gz"],
            BypassReason::OptimizationRecord,
        );
    }

    #[test]
    fn bypasses_file_diagnostics() {
        for option in [
            "-fdiagnostics-format=sarif-file",
            "-fdiagnostics-format=sarif-stderr",
            "-fdiagnostics-file=main.diag",
            "-fdiagnostics-add-output=sarif:file=main.sarif",
        ] {
            assert_bypass(&[option], BypassReason::FileDiagnostic);
        }
    }

    #[test]
    fn bypasses_autofdo_inputs() {
        for option in
            ["-fauto-profile", "-fauto-profile=profile.afdo", "-fprofile-sample-use=profile.afdo"]
        {
            assert_bypass(&[option], BypassReason::AutoFdo);
        }
    }

    #[test]
    fn bypasses_argument_carriers() {
        for option in [
            "-Wp,-DVALUE=1",
            "-Wa,--compress-debug-sections",
            "-Wa,--fatal-warnings",
            "-Wa,-a=listing.lst",
            "-Wl,-rpath,/tmp/lib",
        ] {
            assert_bypass(&[option], BypassReason::ArgumentCarrier);
        }
        for (option, value) in [
            ("-Wp", "-DVALUE=1"),
            ("-Wa", "--compress-debug-sections"),
            ("-Wl", "-rpath"),
            ("-Xpreprocessor", "-DVALUE=1"),
            ("-Xassembler", "--compress-debug-sections"),
            ("-Xlinker", "-rpath"),
        ] {
            assert_bypass(&[option, value], BypassReason::ArgumentCarrier);
        }
    }

    #[test]
    fn rejects_empty_instrumentation_values() {
        for option in
            ["-fsanitize=", "-fno-sanitize=", "-fsanitize-recover=", "-fno-sanitize-recover="]
        {
            assert_bypass(&[option], BypassReason::UnknownOption(OsString::from(option)));
        }
    }

    #[test]
    fn bypasses_plugins_specs_and_unknown_options() {
        for option in
            ["-fplugin=checker.so", "-fplugin-arg-checker-mode=strict", "-specs=custom.specs"]
        {
            assert_bypass(&[option], BypassReason::PluginOrSpecs);
        }
        for option in ["-funknown-semantic", "-Wunknown-warning", "-munknown-target", "-Ounknown"] {
            assert_bypass(&[option], BypassReason::UnknownOption(OsString::from(option)));
        }
    }

    #[test]
    fn bypasses_stdout_depfiles() {
        assert_bypass(&["-MD", "-MF", "-"], BypassReason::StdoutDepfile);
        assert_bypass(&["-MD", "-MF-"], BypassReason::StdoutDepfile);
    }

    #[test]
    fn probe_strips_dependency_flags_and_keeps_module_search_order() {
        let parsed =
            parse_args(&args(&["-c", "-cpp", "-Ione", "-Jorig", "-MD", "-MFuser.d", "main.f90"]))
                .unwrap();
        let probe =
            parsed.dependency_probe_argv(OsStr::new("internal.d"), OsStr::new("private")).unwrap();
        assert_eq!(
            probe,
            args(&[
                "-I",
                "one",
                "-I",
                "orig",
                "-fsyntax-only",
                "-cpp",
                "-Werror=date-time",
                "-MD",
                "-MF",
                "internal.d",
                "-J",
                "private",
                "main.f90",
            ])
        );
    }

    #[test]
    fn probe_appends_original_module_dir_after_explicit_includes() {
        for command in [
            ["-c", "-cpp", "-J", "jmods", "-I", "explicit", "main.f90"],
            ["-c", "-cpp", "-I", "explicit", "-J", "jmods", "main.f90"],
        ] {
            let parsed = parse_args(&args(&command)).unwrap();
            let probe = parsed
                .dependency_probe_argv(OsStr::new("internal.d"), OsStr::new("private"))
                .unwrap();
            assert_eq!(
                probe,
                args(&[
                    "-I",
                    "explicit",
                    "-I",
                    "jmods",
                    "-fsyntax-only",
                    "-cpp",
                    "-Werror=date-time",
                    "-MD",
                    "-MF",
                    "internal.d",
                    "-J",
                    "private",
                    "main.f90",
                ]),
                "command: {command:?}"
            );
        }
    }

    #[test]
    fn duplicate_module_directories_bypass() {
        assert_bypass(&["-J", "a", "-J", "b"], BypassReason::DuplicateModuleDirectory);
        assert_bypass(&["-Ja", "-Jb"], BypassReason::DuplicateModuleDirectory);
        assert_bypass(&["-J", "same", "-J", "same"], BypassReason::DuplicateModuleDirectory);
    }

    #[test]
    fn automatic_source_builds_identity_and_dependency_probes() {
        let parsed =
            parse_args(&args(&["-c", "-DVALUE=1", "-Ione", "-Jmodules", "main.f90"])).unwrap();
        assert_eq!(parsed.preprocessing, Preprocessing::Auto);
        assert_eq!(
            parsed.preprocessor_identity_argv().unwrap(),
            args(&[
                "-DVALUE=1",
                "-I",
                "one",
                "-I",
                "modules",
                "-cpp",
                "-Werror=date-time",
                "-E",
                "-P",
                "main.f90",
            ])
        );
        assert!(
            parsed.dependency_probe_argv(OsStr::new("internal.d"), OsStr::new("private")).is_ok()
        );

        let explicit = parse_args(&args(&["-c", "-cpp", "-DVALUE=1", "main.F90"])).unwrap();
        assert_eq!(
            explicit.preprocessor_observation_argv().unwrap(),
            args(&["-DVALUE=1", "-cpp", "-Werror=date-time", "-E", "-P", "main.F90",])
        );
    }

    #[test]
    fn probe_preserves_wsjtx_macos_semantic_options() {
        let parsed = parse_args(&args(&[
            "-c",
            "-cpp",
            "-isysroot",
            "/Applications/Xcode.app/SDKs/MacOSX.sdk",
            "-mmacosx-version-min=12.0",
            "-fno-f2c",
            "-ffpe-summary=invalid,zero,overflow",
            "-Wno-conversion",
            "-Wno-c-binding-type",
            "-Wno-aliasing",
            "-Wno-unused-dummy-argument",
            "-fno-second-underscore",
            "-fvisibility=hidden",
            "-O3",
            "-funroll-loops",
            "-Wall",
            "-Jmodules",
            "-fopenmp",
            "main.F90",
        ]))
        .unwrap();
        let probe =
            parsed.dependency_probe_argv(OsStr::new("internal.d"), OsStr::new("private")).unwrap();
        assert_eq!(
            probe,
            args(&[
                "-isysroot",
                "/Applications/Xcode.app/SDKs/MacOSX.sdk",
                "-mmacosx-version-min=12.0",
                "-fno-f2c",
                "-ffpe-summary=invalid,zero,overflow",
                "-Wno-conversion",
                "-Wno-c-binding-type",
                "-Wno-aliasing",
                "-Wno-unused-dummy-argument",
                "-fno-second-underscore",
                "-fvisibility=hidden",
                "-O3",
                "-funroll-loops",
                "-Wall",
                "-fopenmp",
                "-I",
                "modules",
                "-fsyntax-only",
                "-cpp",
                "-Werror=date-time",
                "-MD",
                "-MF",
                "internal.d",
                "-J",
                "private",
                "main.F90",
            ])
        );
    }

    #[test]
    fn derives_default_user_depfile_and_replays_make_target_options() {
        let parsed = parse_args(&args(&[
            "-c",
            "-cpp",
            "-MD",
            "-MT",
            "custom target",
            "-MQ",
            "quoted target",
            "-MQquoted target",
            "-MP",
            "-MTsecond",
            "-MP",
            "-o",
            "objects/main.o",
            "main.F90",
        ]))
        .unwrap();
        assert_eq!(parsed.cacheability, Cacheability::Cacheable);
        assert_eq!(parsed.user_depfile, Some(OsString::from("objects/main.d")));
        assert_eq!(parsed.dependency_mode, Some(DependencyMode::Md));
        assert_eq!(
            parsed.dependency_target_modifiers,
            args(&[
                "-MT",
                "custom target",
                "-MQ",
                "quoted target",
                "-MQquoted target",
                "-MP",
                "-MTsecond",
                "-MP",
            ])
        );
        let probe =
            parsed.dependency_probe_argv(OsStr::new("internal.d"), OsStr::new("private")).unwrap();
        assert_eq!(
            probe,
            args(&[
                "-fsyntax-only",
                "-cpp",
                "-Werror=date-time",
                "-MD",
                "-MF",
                "internal.d",
                "-J",
                "private",
                "-MT",
                "custom target",
                "-MQ",
                "quoted target",
                "-MQquoted target",
                "-MP",
                "-MTsecond",
                "-MP",
                "-o",
                "objects/main.o",
                "main.F90",
            ])
        );
    }

    #[test]
    fn last_dependency_mode_wins() {
        let md = parse_args(&args(&["-c", "-MMD", "-MD", "main.f90"])).unwrap();
        assert_eq!(md.dependency_mode, Some(DependencyMode::Md));

        let mmd = parse_args(&args(&["-c", "-MD", "-MMD", "main.f90"])).unwrap();
        assert_eq!(mmd.dependency_mode, Some(DependencyMode::Mmd));
    }

    #[test]
    fn rejects_fpreprocessed_dependency_probes() {
        let parsed = parse_args(&args(&["-c", "-fpreprocessed", "main.f90"])).unwrap();
        assert_eq!(parsed.preprocessing, Preprocessing::Fpreprocessed);
        assert!(!parsed.preprocessing.permits_probe());
        assert_eq!(
            parsed.dependency_probe_argv(OsStr::new("internal.d"), OsStr::new("private")),
            Err(ProbeError::NotProbeable(BypassReason::MissingDependencyProbePreprocessing))
        );
    }
}
