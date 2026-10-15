use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ParseError {
    #[error("unterminated quote")]
    UnterminatedQuote,
    #[error("unsupported shell syntax")]
    UnsupportedSyntax,
    #[error("input is too long")]
    TooLong,
}

pub fn parse(input: &str, max_bytes: usize) -> Result<Vec<String>, ParseError> {
    parse_internal(input, max_bytes, false)
}

pub fn parse_shell(input: &str, max_bytes: usize) -> Result<Vec<String>, ParseError> {
    parse_internal(input, max_bytes, true)
}

fn finish_word(words: &mut Vec<String>, current: &mut String, protected: &mut bool, mark: bool) {
    let mut word = std::mem::take(current);
    if mark
        && *protected
        && matches!(
            word.as_str(),
            "|" | "&&"
                | "||"
                | ";"
                | ">"
                | ">>"
                | "for"
                | "in"
                | "do"
                | "done"
                | "if"
                | "then"
                | "else"
                | "fi"
        )
    {
        word.insert(0, '\u{001f}');
    }
    words.push(word);
    *protected = false;
}

fn parse_internal(input: &str, max_bytes: usize, mark: bool) -> Result<Vec<String>, ParseError> {
    if input.len() > max_bytes {
        return Err(ParseError::TooLong);
    }
    let mut words = Vec::new();
    let mut current = String::new();
    let mut quote = None;
    let mut escaped = false;
    let mut has_word = false;
    let mut protected = false;
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        if escaped {
            protected = true;
            if mark && ch == '$' {
                current.push('\u{001e}');
            }
            if quote == Some('"') && !matches!(ch, '$' | '`' | '"' | '\\') {
                current.push('\\');
            }
            current.push(ch);
            escaped = false;
            has_word = true;
            continue;
        }
        match quote {
            Some('\'') => match ch {
                '\'' => quote = None,
                '$' if mark => {
                    current.push('\u{001e}');
                    current.push(ch);
                }
                _ => current.push(ch),
            },
            Some('"') => match ch {
                '"' => quote = None,
                '\\' => escaped = true,
                '`' => return Err(ParseError::UnsupportedSyntax),
                '$' if chars.peek() == Some(&'(') => {
                    consume_arithmetic_expansion(&mut chars, &mut current)?;
                    has_word = true;
                }
                _ => current.push(ch),
            },
            None => match ch {
                '\\' => {
                    escaped = true;
                    has_word = true;
                }
                '\'' | '"' => {
                    quote = Some(ch);
                    protected = true;
                    has_word = true;
                }
                ' ' | '\t' => {
                    if has_word {
                        finish_word(&mut words, &mut current, &mut protected, mark);
                        has_word = false;
                    }
                }
                '>' => {
                    if has_word {
                        finish_word(&mut words, &mut current, &mut protected, mark);
                        has_word = false;
                    }
                    if chars.peek() == Some(&'>') {
                        chars.next();
                        words.push(">>".into());
                    } else {
                        words.push(">".into());
                    }
                }
                '|' | '&' | ';' => {
                    if has_word {
                        finish_word(&mut words, &mut current, &mut protected, mark);
                        has_word = false;
                    }
                    if ch == ';' {
                        words.push(";".into());
                    } else if chars.peek() == Some(&ch) {
                        chars.next();
                        words.push(if ch == '|' { "||" } else { "&&" }.into());
                    } else if ch == '|' {
                        words.push("|".into());
                    } else {
                        return Err(ParseError::UnsupportedSyntax);
                    }
                }
                '<' | '`' => return Err(ParseError::UnsupportedSyntax),
                '$' if chars.peek() == Some(&'(') => {
                    consume_arithmetic_expansion(&mut chars, &mut current)?;
                    has_word = true;
                }
                _ => {
                    current.push(ch);
                    has_word = true;
                }
            },
            Some(_) => unreachable!(),
        }
    }
    if quote.is_some() || escaped {
        return Err(ParseError::UnterminatedQuote);
    }
    if has_word {
        finish_word(&mut words, &mut current, &mut protected, mark);
    }
    Ok(words)
}

fn consume_arithmetic_expansion(
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
    current: &mut String,
) -> Result<(), ParseError> {
    chars.next();
    if chars.next_if_eq(&'(').is_none() {
        return Err(ParseError::UnsupportedSyntax);
    }
    current.push_str("$((");
    let mut nested_parentheses = 0_usize;
    loop {
        let Some(ch) = chars.next() else {
            return Err(ParseError::UnsupportedSyntax);
        };
        match ch {
            '(' => {
                nested_parentheses += 1;
                current.push(ch);
            }
            ')' if nested_parentheses > 0 => {
                nested_parentheses -= 1;
                current.push(ch);
            }
            ')' if chars.peek() == Some(&')') => {
                chars.next();
                current.push_str("))");
                return Ok(());
            }
            _ => current.push(ch),
        }
    }
}
