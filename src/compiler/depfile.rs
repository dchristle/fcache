//! GNU Make dependency-file parsing.

use thiserror::Error;

/// A decoded GNU Make dependency file.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Depfile {
    /// Rules in file order.
    pub rules: Vec<DepfileRule>,
}

/// A decoded dependency-file rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DepfileRule {
    /// Rule targets in source order.
    pub targets: Vec<Vec<u8>>,
    /// Rule prerequisites in source order.
    pub prerequisites: Vec<Vec<u8>>,
}

impl DepfileRule {
    /// Whether this is an ordinary empty-prerequisite rule such as one emitted by `-MP`.
    pub fn is_dummy(&self) -> bool {
        self.prerequisites.is_empty()
    }
}

/// Errors produced while decoding a dependency file.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum DepfileError {
    #[error("dependency rule has no target")]
    MissingTarget,
    #[error("dependency rule has no separator")]
    MissingSeparator,
}

/// Parse a GNU Make dependency file without requiring UTF-8 paths.
pub fn parse(input: &[u8]) -> Result<Depfile, DepfileError> {
    let logical = join_continuations(input);
    let mut result = Depfile::default();
    for line in logical.split(|byte| *byte == b'\n' || *byte == b'\r') {
        let line = strip_comment(line);
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let Some(separator) = rule_separator(&line) else {
            return Err(DepfileError::MissingSeparator);
        };
        let left = decode_words(&line[..separator]);
        let right = decode_words(&line[separator + 1..]);
        if left.is_empty() {
            return Err(DepfileError::MissingTarget);
        }
        result.rules.push(DepfileRule { targets: left, prerequisites: right });
    }
    Ok(result)
}

/// Alias retained for callers that use the more explicit name.
pub fn parse_depfile(input: &[u8]) -> Result<Depfile, DepfileError> {
    parse(input)
}

fn join_continuations(input: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(input.len());
    let mut index = 0;
    while index < input.len() {
        if input[index] == b'\\' && index + 1 < input.len() {
            if input[index + 1] == b'\n' {
                index += 2;
                while index < input.len() && (input[index] == b' ' || input[index] == b'\t') {
                    index += 1;
                }
                output.push(b' ');
                continue;
            }
            if input[index + 1] == b'\r' {
                index += 2;
                if index < input.len() && input[index] == b'\n' {
                    index += 1;
                }
                while index < input.len() && (input[index] == b' ' || input[index] == b'\t') {
                    index += 1;
                }
                output.push(b' ');
                continue;
            }
        }
        output.push(input[index]);
        index += 1;
    }
    output
}

fn strip_comment(line: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(line.len());
    for (index, &byte) in line.iter().enumerate() {
        if byte == b'#' && preceding_backslashes(line, index) % 2 == 0 {
            break;
        }
        output.push(byte);
    }
    output
}

fn rule_separator(line: &[u8]) -> Option<usize> {
    for (index, &byte) in line.iter().enumerate() {
        if byte == b':'
            && preceding_backslashes(line, index) % 2 == 0
            && line.get(index + 1).is_none_or(|next| next.is_ascii_whitespace())
        {
            return Some(index);
        }
    }
    None
}

fn preceding_backslashes(input: &[u8], index: usize) -> usize {
    input[..index].iter().rev().take_while(|byte| **byte == b'\\').count()
}

fn decode_words(input: &[u8]) -> Vec<Vec<u8>> {
    let mut words = Vec::new();
    let mut word = Vec::new();
    let mut index = 0;
    while index < input.len() {
        let byte = input[index];
        if byte.is_ascii_whitespace() {
            if !word.is_empty() {
                words.push(std::mem::take(&mut word));
            }
            index += 1;
            continue;
        }
        if byte == b'\\' && index + 1 < input.len() {
            word.push(input[index + 1]);
            index += 2;
            continue;
        }
        if byte == b'$' && input.get(index + 1) == Some(&b'$') {
            word.push(b'$');
            index += 2;
            continue;
        }
        word.push(byte);
        index += 1;
    }
    if !word.is_empty() {
        words.push(word);
    }
    words
}

#[cfg(test)]
mod tests {
    use super::{DepfileRule, parse};

    #[test]
    fn parses_escaped_paths_and_preserves_rule_boundaries() {
        let parsed =
            parse(b"x.o y.mod: src\\ file.f90 inc\\#x\\$y\\\\z \\\n  more.f90\n.PHONY: all\n")
                .unwrap();
        assert_eq!(
            parsed.rules,
            vec![
                DepfileRule {
                    targets: vec![b"x.o".to_vec(), b"y.mod".to_vec()],
                    prerequisites: vec![
                        b"src file.f90".to_vec(),
                        b"inc#x$y\\z".to_vec(),
                        b"more.f90".to_vec(),
                    ],
                },
                DepfileRule {
                    targets: vec![b".PHONY".to_vec()],
                    prerequisites: vec![b"all".to_vec()],
                },
            ]
        );
    }

    #[test]
    fn treats_literal_phony_target_as_an_ordinary_dependency_rule() {
        let parsed = parse(b".PHONY: source.F90 value.inc\n").unwrap();
        assert_eq!(parsed.rules[0].targets, vec![b".PHONY".to_vec()]);
        assert_eq!(
            parsed.rules[0].prerequisites,
            vec![b"source.F90".to_vec(), b"value.inc".to_vec()]
        );
    }

    #[test]
    fn preserves_dummy_rules_without_inferring_module_outputs() {
        let parsed = parse(b"custom.mod: main.f90\nused.mod:\n").unwrap();
        assert_eq!(parsed.rules.len(), 2);
        assert_eq!(parsed.rules[0].targets, vec![b"custom.mod".to_vec()]);
        assert!(!parsed.rules[0].is_dummy());
        assert_eq!(parsed.rules[1].targets, vec![b"used.mod".to_vec()]);
        assert!(parsed.rules[1].is_dummy());
    }

    #[test]
    fn preserves_non_utf8_path_bytes() {
        let parsed = parse(b"target\xff.o: source\xfe.f90\n").unwrap();
        assert_eq!(parsed.rules[0].targets, vec![b"target\xff.o".to_vec()]);
        assert_eq!(parsed.rules[0].prerequisites, vec![b"source\xfe.f90".to_vec()]);
    }

    #[test]
    fn does_not_treat_colon_without_following_space_as_separator() {
        assert!(parse(b"x.o:y.f90\n").is_err());
    }
}
