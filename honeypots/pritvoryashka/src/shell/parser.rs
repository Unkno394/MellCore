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
    if input.len() > max_bytes {
        return Err(ParseError::TooLong);
    }
    let mut words = Vec::new();
    let mut current = String::new();
    let mut quote = None;
    let mut escaped = false;
    let mut has_word = false;
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        if escaped {
            current.push(ch);
            escaped = false;
            has_word = true;
            continue;
        }
        match quote {
            Some('\'') => match ch {
                '\'' => quote = None,
                _ => current.push(ch),
            },
            Some('"') => match ch {
                '"' => quote = None,
                '\\' => escaped = true,
                '`' => return Err(ParseError::UnsupportedSyntax),
                '$' if chars.peek() == Some(&'(') => return Err(ParseError::UnsupportedSyntax),
                _ => current.push(ch),
            },
            None => match ch {
                '\\' => {
                    escaped = true;
                    has_word = true;
                }
                '\'' | '"' => {
                    quote = Some(ch);
                    has_word = true;
                }
                ' ' | '\t' => {
                    if has_word {
                        words.push(std::mem::take(&mut current));
                        has_word = false;
                    }
                }
                '>' => {
                    if has_word {
                        words.push(std::mem::take(&mut current));
                        has_word = false;
                    }
                    if chars.peek() == Some(&'>') {
                        chars.next();
                        words.push(">>".into());
                    } else {
                        words.push(">".into());
                    }
                }
                '|' | '&' | ';' | '<' | '`' => {
                    return Err(ParseError::UnsupportedSyntax);
                }
                '$' if chars.peek() == Some(&'(') => {
                    return Err(ParseError::UnsupportedSyntax);
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
        words.push(current);
    }
    Ok(words)
}
