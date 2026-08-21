//! Conservative gfortran dependency search-resolution proofs.

use std::ffi::{OsStr, OsString};
use std::path::{Component, Path, PathBuf};

use thiserror::Error;

use super::{Cacheability, GfortranInvocation};

/// A command-line directory search tier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SearchPathKind {
    Quote,
    Include,
    System,
    After,
}

/// A byte-preserving command-line search path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SearchPath {
    pub kind: SearchPathKind,
    pub path: OsString,
}

/// The preprocessing action that injects a file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ForcedInputKind {
    Include,
    Imacros,
}

/// A byte-preserving file named by `-include` or `-imacros`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForcedInput {
    pub kind: ForcedInputKind,
    pub path: OsString,
}

/// Search paths obtained outside argv, in compiler search order within each tier.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EnvironmentSearchPaths {
    pub quote: Vec<OsString>,
    pub include: Vec<OsString>,
    pub system: Vec<OsString>,
    pub after: Vec<OsString>,
    pub modules: Vec<OsString>,
    pub intrinsic_modules: Vec<OsString>,
    /// False unless all search-affecting environment and compiler-default paths were modeled.
    pub complete: bool,
}

impl EnvironmentSearchPaths {
    /// An explicitly verified environment with no additional search paths.
    pub fn complete_empty() -> Self {
        Self { complete: true, ..Self::default() }
    }
}

/// Source constructs relevant to filesystem search that were found in all observed inputs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ObservedSearchFeatures {
    scan_complete: bool,
    include_next: bool,
    has_include: bool,
    token_pasting: bool,
}

impl ObservedSearchFeatures {
    /// Conservatively scan every observed source and included input.
    pub fn scan<'a>(inputs: impl IntoIterator<Item = &'a [u8]>) -> Self {
        let mut features = Self { scan_complete: true, ..Self::default() };
        for input in inputs {
            features.observe(input);
        }
        features
    }

    /// Whether compiler depfiles can enumerate every filesystem query in these inputs.
    pub fn permits_complete_depfile_observation(&self) -> bool {
        self.scan_complete && !self.has_include && !self.token_pasting
    }

    fn observe(&mut self, input: &[u8]) {
        let input = join_line_splices(input);
        for line in input.split(|byte| *byte == b'\n') {
            let directive = line
                .iter()
                .position(|byte| !matches!(byte, b' ' | b'\t' | 0x0b | 0x0c | b'\r'))
                .is_some_and(|index| line[index] == b'#');
            if !directive {
                continue;
            }
            self.include_next |= contains_bytes(line, b"include_next");
            self.has_include |= contains_bytes(line, b"__has_include");
            self.token_pasting |= contains_bytes(line, b"##");
        }
    }
}

/// Inputs needed to construct ordered search chains for a prior compiler observation.
#[derive(Clone, Copy, Debug)]
pub struct ResolutionContext<'a> {
    pub cwd: &'a Path,
    /// Parent directories of every compiler-observed include, in depfile order.
    pub include_parents: &'a [PathBuf],
    pub environment: &'a EnvironmentSearchPaths,
    pub observed_features: &'a ObservedSearchFeatures,
}

/// The origin of a modeled search root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SearchRootOrigin {
    SourceDirectory,
    IncludeParent(usize),
    WorkingDirectory,
    CommandLine(SearchPathKind, usize),
    ModuleOutput,
    IntrinsicModule(usize),
    EnvironmentQuote(usize),
    EnvironmentInclude(usize),
    EnvironmentSystem(usize),
    EnvironmentAfter(usize),
    EnvironmentModule(usize),
    EnvironmentIntrinsicModule(usize),
}

/// An absolute lexical search root and its source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SearchRoot {
    pub origin: SearchRootOrigin,
    pub path: PathBuf,
}

/// Ordered search chains used only to validate a compiler-authoritative observation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SearchResolutionModel {
    pub quoted_include_roots: Vec<SearchRoot>,
    pub angle_include_roots: Vec<SearchRoot>,
    pub forced_include_roots: Vec<SearchRoot>,
    pub module_roots: Vec<SearchRoot>,
    pub intrinsic_module_roots: Vec<SearchRoot>,
    pub forced_inputs: Vec<ForcedInput>,
    cwd: PathBuf,
    source: PathBuf,
}

/// How a compiler-observed prerequisite was resolved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DependencyResolutionKind {
    Source,
    Include,
    ForcedInput(usize),
    Module,
    Submodule,
    IntrinsicModule,
    ModuleOrInclude,
}

/// A raw depfile prerequisite correlated with the path consumed by the slow probe.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DependencyObservation {
    pub prerequisite: Vec<u8>,
    pub resolved_path: PathBuf,
    pub kind: DependencyResolutionKind,
}

/// The selected file and all modeled roots that could have selected it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelectedPathWitness {
    pub prerequisite: Vec<u8>,
    pub selected_path: PathBuf,
    pub kind: DependencyResolutionKind,
    pub possible_roots: Vec<SearchRoot>,
}

/// A path that must remain absent so it cannot shadow a previously selected file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NegativePathWitness {
    pub prerequisite: Vec<u8>,
    pub path: PathBuf,
}

/// Positive selections and conservative earlier negative candidates.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ResolutionProof {
    pub selected: Vec<SelectedPathWitness>,
    pub negative_candidates: Vec<NegativePathWitness>,
}

/// Why a compiler observation cannot use compiler-free direct validation.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum DirectIneligibleReason {
    #[error("the invocation is not cacheable")]
    InvocationNotCacheable,
    #[error("search-affecting argument {0:?} is not modeled")]
    UnmodeledArgument(OsString),
    #[error("search-affecting environment or compiler defaults are incomplete")]
    UnmodeledEnvironment,
    #[error("the observed-input search-feature scan is incomplete")]
    IncompleteFeatureScan,
    #[error("include_next cannot be proven from a depfile")]
    IncludeNext,
    #[error("__has_include filesystem queries cannot be proven from a depfile")]
    HasInclude,
    #[error("preprocessor token pasting can hide filesystem query operators")]
    TokenPasting,
    #[error("dependency observation has an unsupported path encoding")]
    UnsupportedPathEncoding,
    #[error("forced-input observation refers to missing argument index {0}")]
    UnknownForcedInput(usize),
    #[error("forced input at argument index {0} is absent from the authoritative observation")]
    MissingForcedInput(usize),
    #[error("the working directory must be absolute")]
    RelativeWorkingDirectory,
    #[error("dependency prerequisite {0:?} has no complete modeled resolution")]
    UnresolvedPrerequisite(Vec<u8>),
}

impl GfortranInvocation {
    /// Whether depfiles can represent filesystem queries from both source and arguments.
    pub fn permits_complete_depfile_observation(
        &self,
        observed_features: &ObservedSearchFeatures,
    ) -> bool {
        if !observed_features.permits_complete_depfile_observation() {
            return false;
        }
        let argument_features = self.argument_search_features();
        !argument_features.has_include && !argument_features.token_pasting
    }

    fn argument_search_features(&self) -> ObservedSearchFeatures {
        let mut features =
            ObservedSearchFeatures { scan_complete: true, ..ObservedSearchFeatures::default() };
        for argument in &self.original_args {
            let argument = encoded(argument);
            features.include_next |= contains_bytes(&argument, b"include_next");
            features.has_include |= contains_bytes(&argument, b"__has_include");
            features.token_pasting |= contains_bytes(&argument, b"##");
        }
        features
    }

    /// Build conservative ordered search chains without changing compiler probe argv.
    pub fn search_resolution_model(
        &self,
        context: ResolutionContext<'_>,
    ) -> Result<SearchResolutionModel, DirectIneligibleReason> {
        if !matches!(self.cacheability, Cacheability::Cacheable) {
            return Err(DirectIneligibleReason::InvocationNotCacheable);
        }
        if !context.cwd.is_absolute() {
            return Err(DirectIneligibleReason::RelativeWorkingDirectory);
        }
        if let Some(argument) = &self.unmodeled_search_argument {
            return Err(DirectIneligibleReason::UnmodeledArgument(argument.clone()));
        }
        if !context.environment.complete {
            return Err(DirectIneligibleReason::UnmodeledEnvironment);
        }
        if !context.observed_features.scan_complete {
            return Err(DirectIneligibleReason::IncompleteFeatureScan);
        }
        if context.observed_features.include_next {
            return Err(DirectIneligibleReason::IncludeNext);
        }
        if context.observed_features.has_include {
            return Err(DirectIneligibleReason::HasInclude);
        }
        if context.observed_features.token_pasting {
            return Err(DirectIneligibleReason::TokenPasting);
        }
        let argument_features = self.argument_search_features();
        if argument_features.include_next {
            return Err(DirectIneligibleReason::IncludeNext);
        }
        if argument_features.has_include {
            return Err(DirectIneligibleReason::HasInclude);
        }
        if argument_features.token_pasting {
            return Err(DirectIneligibleReason::TokenPasting);
        }

        let cwd = absolute_root(context.cwd, OsStr::new(""));
        let source = self
            .source
            .as_deref()
            .map(|source| absolute_root(&cwd, source))
            .ok_or(DirectIneligibleReason::InvocationNotCacheable)?;
        let source_parent = source.parent().unwrap_or(&cwd).to_path_buf();

        let mut include_parents =
            vec![SearchRoot { origin: SearchRootOrigin::SourceDirectory, path: source_parent }];
        include_parents.extend(context.include_parents.iter().enumerate().map(|(index, path)| {
            SearchRoot {
                origin: SearchRootOrigin::IncludeParent(index),
                path: absolute_root(&cwd, path.as_os_str()),
            }
        }));
        include_parents
            .push(SearchRoot { origin: SearchRootOrigin::WorkingDirectory, path: cwd.clone() });

        let command_line = |kind| {
            self.search_paths
                .iter()
                .enumerate()
                .filter(move |(_, search)| search.kind == kind)
                .map(|(index, search)| SearchRoot {
                    origin: SearchRootOrigin::CommandLine(kind, index),
                    path: absolute_root(&cwd, &search.path),
                })
                .collect::<Vec<_>>()
        };
        let quote = command_line(SearchPathKind::Quote);
        let include = command_line(SearchPathKind::Include);
        let system = command_line(SearchPathKind::System);
        let after = command_line(SearchPathKind::After);

        let environment_quote =
            environment_roots(&cwd, &context.environment.quote, SearchRootOrigin::EnvironmentQuote);
        let environment_include = environment_roots(
            &cwd,
            &context.environment.include,
            SearchRootOrigin::EnvironmentInclude,
        );
        let environment_system = environment_roots(
            &cwd,
            &context.environment.system,
            SearchRootOrigin::EnvironmentSystem,
        );
        let environment_after =
            environment_roots(&cwd, &context.environment.after, SearchRootOrigin::EnvironmentAfter);

        let mut angle_include_roots = include.clone();
        angle_include_roots.extend(environment_include.clone());
        angle_include_roots.extend(system.clone());
        angle_include_roots.extend(environment_system.clone());
        angle_include_roots.extend(after.clone());
        angle_include_roots.extend(environment_after.clone());

        let mut quoted_include_roots = include_parents.clone();
        quoted_include_roots.extend(quote);
        quoted_include_roots.extend(environment_quote);
        quoted_include_roots.extend(angle_include_roots.clone());

        let mut forced_include_roots =
            vec![SearchRoot { origin: SearchRootOrigin::WorkingDirectory, path: cwd.clone() }];
        forced_include_roots.extend(quoted_include_roots.clone());

        let mut module_roots =
            vec![SearchRoot { origin: SearchRootOrigin::WorkingDirectory, path: cwd.clone() }];
        module_roots.extend(include);
        if let Some(module_dir) = &self.module_dir {
            module_roots.push(SearchRoot {
                origin: SearchRootOrigin::ModuleOutput,
                path: absolute_root(&cwd, module_dir),
            });
        }
        module_roots.extend(environment_roots(
            &cwd,
            &context.environment.modules,
            SearchRootOrigin::EnvironmentModule,
        ));

        let mut intrinsic_module_roots = self
            .intrinsic_module_dirs
            .iter()
            .enumerate()
            .map(|(index, path)| SearchRoot {
                origin: SearchRootOrigin::IntrinsicModule(index),
                path: absolute_root(&cwd, path),
            })
            .collect::<Vec<_>>();
        intrinsic_module_roots.extend(environment_roots(
            &cwd,
            &context.environment.intrinsic_modules,
            SearchRootOrigin::EnvironmentIntrinsicModule,
        ));

        Ok(SearchResolutionModel {
            quoted_include_roots,
            angle_include_roots,
            forced_include_roots,
            module_roots,
            intrinsic_module_roots,
            forced_inputs: self.forced_inputs.clone(),
            cwd,
            source,
        })
    }
}

impl SearchResolutionModel {
    /// Derive every earlier candidate that could shadow an authoritative selected input.
    pub fn prove(
        &self,
        observations: &[DependencyObservation],
    ) -> Result<ResolutionProof, DirectIneligibleReason> {
        let mut proof = ResolutionProof::default();
        let mut observed_forced_inputs = vec![false; self.forced_inputs.len()];
        for observation in observations {
            if let DependencyResolutionKind::ForcedInput(index) = observation.kind {
                if index >= self.forced_inputs.len() {
                    return Err(DirectIneligibleReason::UnknownForcedInput(index));
                }
            }
            if observation.kind == DependencyResolutionKind::Source {
                let prerequisite = path_from_bytes(&observation.prerequisite)?;
                let prerequisite = absolute_root(&self.cwd, prerequisite.as_os_str());
                let resolved = absolute_root(&self.cwd, observation.resolved_path.as_os_str());
                if prerequisite != self.source && resolved != self.source {
                    return Err(DirectIneligibleReason::UnresolvedPrerequisite(
                        observation.prerequisite.clone(),
                    ));
                }
                proof.selected.push(SelectedPathWitness {
                    prerequisite: observation.prerequisite.clone(),
                    selected_path: resolved,
                    kind: observation.kind,
                    possible_roots: Vec::new(),
                });
                continue;
            }

            let chains: &[&[SearchRoot]] = match observation.kind {
                DependencyResolutionKind::Source => unreachable!(),
                DependencyResolutionKind::Include => {
                    &[&self.quoted_include_roots, &self.angle_include_roots]
                }
                DependencyResolutionKind::ForcedInput(_) => &[&self.forced_include_roots],
                DependencyResolutionKind::Module | DependencyResolutionKind::Submodule => {
                    &[&self.module_roots]
                }
                DependencyResolutionKind::IntrinsicModule => &[&self.intrinsic_module_roots],
                DependencyResolutionKind::ModuleOrInclude => {
                    &[&self.quoted_include_roots, &self.angle_include_roots, &self.module_roots]
                }
            };
            let module_name_only = matches!(
                observation.kind,
                DependencyResolutionKind::Module
                    | DependencyResolutionKind::Submodule
                    | DependencyResolutionKind::IntrinsicModule
            );
            let required_spelling =
                if let DependencyResolutionKind::ForcedInput(index) = observation.kind {
                    observed_forced_inputs[index] = true;
                    Some(Path::new(&self.forced_inputs[index].path))
                } else {
                    None
                };
            let (possible_roots, negatives) =
                self.resolve_observation(observation, chains, module_name_only, required_spelling)?;
            proof.selected.push(SelectedPathWitness {
                prerequisite: observation.prerequisite.clone(),
                selected_path: absolute_root(&self.cwd, observation.resolved_path.as_os_str()),
                kind: observation.kind,
                possible_roots,
            });
            for path in negatives {
                let witness =
                    NegativePathWitness { prerequisite: observation.prerequisite.clone(), path };
                if !proof.negative_candidates.contains(&witness) {
                    proof.negative_candidates.push(witness);
                }
            }
        }
        if let Some(index) = observed_forced_inputs.iter().position(|observed| !observed) {
            return Err(DirectIneligibleReason::MissingForcedInput(index));
        }
        Ok(proof)
    }

    fn resolve_observation(
        &self,
        observation: &DependencyObservation,
        chains: &[&[SearchRoot]],
        module_name_only: bool,
        required_spelling: Option<&Path>,
    ) -> Result<(Vec<SearchRoot>, Vec<PathBuf>), DirectIneligibleReason> {
        let prerequisite = path_from_bytes(&observation.prerequisite)?;
        let prerequisite = absolute_root(&self.cwd, prerequisite.as_os_str());
        let resolved = absolute_root(&self.cwd, observation.resolved_path.as_os_str());
        let representations = if prerequisite == resolved {
            vec![resolved.clone()]
        } else {
            vec![prerequisite, resolved.clone()]
        };
        let mut possible_roots = Vec::new();
        let mut negatives = Vec::new();

        for chain in chains {
            for (selected_index, selected_root) in chain.iter().enumerate() {
                for representation in &representations {
                    let Ok(suffix) = representation.strip_prefix(&selected_root.path) else {
                        continue;
                    };
                    if suffix.as_os_str().is_empty()
                        || (module_name_only && !is_single_file_name(suffix))
                        || required_spelling.is_some_and(|required| {
                            if required.is_absolute() {
                                representation != required
                            } else {
                                suffix != required
                            }
                        })
                    {
                        continue;
                    }
                    if !possible_roots.contains(selected_root) {
                        possible_roots.push(selected_root.clone());
                    }
                    for earlier_root in &chain[..selected_index] {
                        let candidate = earlier_root.path.join(suffix);
                        if !representations.contains(&candidate) && !negatives.contains(&candidate)
                        {
                            negatives.push(candidate);
                        }
                    }
                }
            }
        }
        if possible_roots.is_empty() {
            return Err(DirectIneligibleReason::UnresolvedPrerequisite(
                observation.prerequisite.clone(),
            ));
        }
        Ok((possible_roots, negatives))
    }
}

fn environment_roots(
    cwd: &Path,
    paths: &[OsString],
    origin: impl Fn(usize) -> SearchRootOrigin,
) -> Vec<SearchRoot> {
    paths
        .iter()
        .enumerate()
        .map(|(index, path)| SearchRoot { origin: origin(index), path: absolute_root(cwd, path) })
        .collect()
}

fn absolute_root(cwd: &Path, value: &OsStr) -> PathBuf {
    if value.is_empty() {
        cwd.to_path_buf()
    } else {
        let path = Path::new(value);
        if path.is_absolute() { path.to_path_buf() } else { cwd.join(path) }
    }
}

fn path_from_bytes(value: &[u8]) -> Result<PathBuf, DirectIneligibleReason> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        Ok(PathBuf::from(OsString::from_vec(value.to_vec())))
    }
    #[cfg(not(unix))]
    {
        String::from_utf8(value.to_vec())
            .map(PathBuf::from)
            .map_err(|_| DirectIneligibleReason::UnsupportedPathEncoding)
    }
}

fn encoded(value: &OsStr) -> Vec<u8> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        value.as_bytes().to_vec()
    }
    #[cfg(not(unix))]
    {
        value.to_string_lossy().into_owned().into_bytes()
    }
}

fn is_single_file_name(path: &Path) -> bool {
    let mut components = path.components();
    matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none()
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|window| window == needle)
}

fn join_line_splices(input: &[u8]) -> Vec<u8> {
    let mut joined = Vec::with_capacity(input.len());
    let mut index = 0;
    while index < input.len() {
        if input[index] == b'\\' && input.get(index + 1) == Some(&b'\n') {
            index += 2;
        } else if input[index] == b'\\'
            && input.get(index + 1) == Some(&b'\r')
            && input.get(index + 2) == Some(&b'\n')
        {
            index += 3;
        } else {
            joined.push(input[index]);
            index += 1;
        }
    }
    joined
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};

    use super::{
        DependencyObservation, DependencyResolutionKind, DirectIneligibleReason,
        EnvironmentSearchPaths, ForcedInput, ForcedInputKind, ObservedSearchFeatures,
        ResolutionContext, SearchPath, SearchPathKind, SearchRootOrigin,
    };
    use crate::compiler::gfortran::parse_args;

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    fn context<'a>(
        parents: &'a [PathBuf],
        environment: &'a EnvironmentSearchPaths,
        features: &'a ObservedSearchFeatures,
    ) -> ResolutionContext<'a> {
        ResolutionContext {
            cwd: Path::new("/work"),
            include_parents: parents,
            environment,
            observed_features: features,
        }
    }

    #[test]
    fn parses_structured_search_arguments_without_reordering_probe_argv() {
        let parsed = parse_args(&args(&[
            "-c",
            "-cpp",
            "-iquote",
            "quote",
            "-Iinclude-one",
            "-isystemsystem",
            "-I",
            "include-two",
            "-idirafter",
            "after",
            "-include",
            "forced.h",
            "-imacrosmacros.h",
            "-fintrinsic-modules-path=intrinsic",
            "-fintrinsic-modules-path",
            "intrinsic-two",
            "-Jmodules",
            "main.F90",
        ]))
        .unwrap();

        assert_eq!(
            parsed.search_paths,
            vec![
                SearchPath { kind: SearchPathKind::Quote, path: OsString::from("quote") },
                SearchPath { kind: SearchPathKind::Include, path: OsString::from("include-one") },
                SearchPath { kind: SearchPathKind::System, path: OsString::from("system") },
                SearchPath { kind: SearchPathKind::Include, path: OsString::from("include-two") },
                SearchPath { kind: SearchPathKind::After, path: OsString::from("after") },
            ]
        );
        assert_eq!(
            parsed.forced_inputs,
            vec![
                ForcedInput { kind: ForcedInputKind::Include, path: OsString::from("forced.h") },
                ForcedInput { kind: ForcedInputKind::Imacros, path: OsString::from("macros.h") },
            ]
        );
        assert_eq!(parsed.intrinsic_module_dirs, args(&["intrinsic", "intrinsic-two"]));
        assert_eq!(
            parsed
                .dependency_probe_argv(
                    OsString::from("probe.d").as_os_str(),
                    OsString::from("private").as_os_str()
                )
                .unwrap(),
            args(&[
                "-iquote",
                "quote",
                "-I",
                "include-one",
                "-isystemsystem",
                "-I",
                "include-two",
                "-idirafter",
                "after",
                "-include",
                "forced.h",
                "-imacrosmacros.h",
                "-fintrinsic-modules-path=intrinsic",
                "-fintrinsic-modules-path",
                "intrinsic-two",
                "-I",
                "modules",
                "-fsyntax-only",
                "-cpp",
                "-Werror=date-time",
                "-MD",
                "-MF",
                "probe.d",
                "-J",
                "private",
                "main.F90",
            ])
        );
    }

    #[test]
    fn constructs_search_tiers_and_places_module_output_after_explicit_includes() {
        let parsed = parse_args(&args(&[
            "-c",
            "-Ione",
            "-Jmodules",
            "-Itwo",
            "-iquotequote",
            "-isystemsystem",
            "main.F90",
        ]))
        .unwrap();
        let parents = vec![PathBuf::from("/work/nested")];
        let environment = EnvironmentSearchPaths {
            include: args(&["env-include"]),
            system: args(&["env-system"]),
            modules: args(&["env-modules"]),
            complete: true,
            ..EnvironmentSearchPaths::default()
        };
        let features = ObservedSearchFeatures::scan([b"program main".as_slice()]);
        let model =
            parsed.search_resolution_model(context(&parents, &environment, &features)).unwrap();

        let module_paths = model.module_roots.iter().map(|root| &root.path).collect::<Vec<_>>();
        assert_eq!(
            module_paths,
            vec![
                &PathBuf::from("/work"),
                &PathBuf::from("/work/one"),
                &PathBuf::from("/work/two"),
                &PathBuf::from("/work/modules"),
                &PathBuf::from("/work/env-modules"),
            ]
        );
        assert_eq!(model.module_roots[3].origin, SearchRootOrigin::ModuleOutput);
        let quoted_paths =
            model.quoted_include_roots.iter().map(|root| &root.path).collect::<Vec<_>>();
        assert_eq!(
            quoted_paths,
            vec![
                &PathBuf::from("/work"),
                &PathBuf::from("/work/nested"),
                &PathBuf::from("/work"),
                &PathBuf::from("/work/quote"),
                &PathBuf::from("/work/one"),
                &PathBuf::from("/work/two"),
                &PathBuf::from("/work/env-include"),
                &PathBuf::from("/work/system"),
                &PathBuf::from("/work/env-system"),
            ]
        );
    }

    #[test]
    fn derives_all_earlier_module_and_include_shadow_candidates() {
        let parsed =
            parse_args(&args(&["-c", "-Iearly", "-Iselected", "-Jmodules", "main.F90"])).unwrap();
        let environment = EnvironmentSearchPaths::complete_empty();
        let features = ObservedSearchFeatures::scan([b"program main".as_slice()]);
        let model = parsed.search_resolution_model(context(&[], &environment, &features)).unwrap();
        let proof = model
            .prove(&[
                DependencyObservation {
                    prerequisite: b"selected/shadow.mod".to_vec(),
                    resolved_path: PathBuf::from("/work/selected/shadow.mod"),
                    kind: DependencyResolutionKind::Module,
                },
                DependencyObservation {
                    prerequisite: b"selected/nested/value.inc".to_vec(),
                    resolved_path: PathBuf::from("/work/selected/nested/value.inc"),
                    kind: DependencyResolutionKind::Include,
                },
            ])
            .unwrap();

        let negatives = proof
            .negative_candidates
            .iter()
            .map(|witness| witness.path.clone())
            .collect::<Vec<_>>();
        assert!(negatives.contains(&PathBuf::from("/work/shadow.mod")));
        assert!(negatives.contains(&PathBuf::from("/work/early/shadow.mod")));
        assert!(negatives.contains(&PathBuf::from("/work/nested/value.inc")));
        assert!(negatives.contains(&PathBuf::from("/work/early/nested/value.inc")));
        assert_eq!(proof.selected.len(), 2);
    }

    #[test]
    fn rejects_incomplete_or_unprovable_search_semantics() {
        let parsed = parse_args(&args(&["-c", "-Iinclude", "main.F90"])).unwrap();
        let environment = EnvironmentSearchPaths::default();
        let features = ObservedSearchFeatures::scan([b"program main".as_slice()]);
        assert_eq!(
            parsed.search_resolution_model(context(&[], &environment, &features)),
            Err(DirectIneligibleReason::UnmodeledEnvironment)
        );

        let environment = EnvironmentSearchPaths::complete_empty();
        let include_next = ObservedSearchFeatures::scan([b"#include_next <value.h>".as_slice()]);
        assert_eq!(
            parsed.search_resolution_model(context(&[], &environment, &include_next)),
            Err(DirectIneligibleReason::IncludeNext)
        );
        let has_include =
            ObservedSearchFeatures::scan([b"#if __has_include(<value.h>)".as_slice()]);
        assert_eq!(
            parsed.search_resolution_model(context(&[], &environment, &has_include)),
            Err(DirectIneligibleReason::HasInclude)
        );
        let spliced_has_include =
            ObservedSearchFeatures::scan([b"#if __has_\\\ninclude(<value.h>)".as_slice()]);
        assert_eq!(
            parsed.search_resolution_model(context(&[], &environment, &spliced_has_include)),
            Err(DirectIneligibleReason::HasInclude)
        );
        let token_pasting =
            ObservedSearchFeatures::scan([b"#define QUERY(a, b) a ## b".as_slice()]);
        assert_eq!(
            parsed.search_resolution_model(context(&[], &environment, &token_pasting)),
            Err(DirectIneligibleReason::TokenPasting)
        );

        let fortran_text = ObservedSearchFeatures::scan([
            b"character(len=*), parameter :: marker = '##' ! __has_include include_next".as_slice(),
        ]);
        assert!(parsed.search_resolution_model(context(&[], &environment, &fortran_text)).is_ok());

        let model = parsed.search_resolution_model(context(&[], &environment, &features)).unwrap();
        assert_eq!(
            model.prove(&[DependencyObservation {
                prerequisite: b"/outside/value.inc".to_vec(),
                resolved_path: PathBuf::from("/outside/value.inc"),
                kind: DependencyResolutionKind::Include,
            }]),
            Err(DirectIneligibleReason::UnresolvedPrerequisite(b"/outside/value.inc".to_vec()))
        );
    }

    #[test]
    fn rejects_search_arguments_with_unmodeled_resolution_rules() {
        let environment = EnvironmentSearchPaths::complete_empty();
        let features = ObservedSearchFeatures::scan([b"program main".as_slice()]);
        for arguments in [vec!["-c", "-I-", "main.F90"], vec!["-c", "-F/frameworks", "main.F90"]] {
            let parsed = parse_args(&args(&arguments)).unwrap();
            assert!(matches!(
                parsed.search_resolution_model(context(&[], &environment, &features)),
                Err(DirectIneligibleReason::UnmodeledArgument(_))
            ));
        }

        let sysroot = parse_args(&args(&["-c", "-isysroot", "/sdk", "main.F90"])).unwrap();
        assert!(sysroot.search_resolution_model(context(&[], &environment, &features)).is_ok());
    }

    #[test]
    fn requires_each_forced_input_to_match_its_configured_spelling() {
        let parsed =
            parse_args(&args(&["-c", "-Iinclude", "-include", "nested/forced.h", "main.F90"]))
                .unwrap();
        let environment = EnvironmentSearchPaths::complete_empty();
        let features = ObservedSearchFeatures::scan([b"program main".as_slice()]);
        let model = parsed.search_resolution_model(context(&[], &environment, &features)).unwrap();
        assert_eq!(model.prove(&[]), Err(DirectIneligibleReason::MissingForcedInput(0)));
        assert_eq!(
            model.prove(&[DependencyObservation {
                prerequisite: b"include/other.h".to_vec(),
                resolved_path: PathBuf::from("/work/include/other.h"),
                kind: DependencyResolutionKind::ForcedInput(0),
            }]),
            Err(DirectIneligibleReason::UnresolvedPrerequisite(b"include/other.h".to_vec()))
        );
        let proof = model
            .prove(&[DependencyObservation {
                prerequisite: b"include/nested/forced.h".to_vec(),
                resolved_path: PathBuf::from("/work/include/nested/forced.h"),
                kind: DependencyResolutionKind::ForcedInput(0),
            }])
            .unwrap();
        assert_eq!(proof.selected.len(), 1);
        assert!(
            proof
                .negative_candidates
                .iter()
                .any(|witness| witness.path == Path::new("/work/nested/forced.h"))
        );
    }

    #[cfg(unix)]
    #[test]
    fn preserves_non_utf8_prerequisite_bytes() {
        use std::os::unix::ffi::OsStringExt;

        let include_dir = OsString::from_vec(b"inc\xff".to_vec());
        let source = OsString::from("main.F90");
        let parsed =
            parse_args(&[OsString::from("-c"), OsString::from("-I"), include_dir, source]).unwrap();
        let environment = EnvironmentSearchPaths::complete_empty();
        let features = ObservedSearchFeatures::scan([b"program main".as_slice()]);
        let model = parsed.search_resolution_model(context(&[], &environment, &features)).unwrap();
        let resolved = PathBuf::from(OsString::from_vec(b"/work/inc\xff/value.inc".to_vec()));
        let proof = model
            .prove(&[DependencyObservation {
                prerequisite: b"inc\xff/value.inc".to_vec(),
                resolved_path: resolved.clone(),
                kind: DependencyResolutionKind::Include,
            }])
            .unwrap();
        assert_eq!(proof.selected[0].selected_path, resolved);
    }
}
