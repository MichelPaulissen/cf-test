/// Parses the dependency side of bounded Makefile-style rustc dep-info.
/// Backslash escapes are decoded without treating Windows separators as escapes.
pub fn parse_makefile_dep_info(input: &str) -> Result<Vec<String>, String> {
    if input.len() > 4 * 1024 * 1024 {
        return Err("dep-info exceeds its bounded parser limit".to_owned());
    }
    let mut logical = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\\' && chars.peek() == Some(&'\n') {
            chars.next();
            logical.push(' ');
        } else if ch == '\\' && chars.peek() == Some(&'\r') {
            chars.next();
            if chars.next() != Some('\n') {
                return Err("dep-info contains a malformed CR continuation".to_owned());
            }
            logical.push(' ');
        } else {
            logical.push(ch);
        }
    }

    let mut dependencies = Vec::new();
    for rule in logical.lines().filter(|line| !line.trim().is_empty()) {
        let separator = rule
            .char_indices()
            .find_map(|(index, ch)| {
                if ch != ':' || is_escaped(rule, index) {
                    return None;
                }
                let drive_prefix = index == 1
                    && rule.as_bytes()[0].is_ascii_alphabetic()
                    && rule
                        .as_bytes()
                        .get(2)
                        .is_some_and(|next| matches!(next, b'/' | b'\\'));
                (!drive_prefix).then_some(index)
            })
            .ok_or_else(|| "dep-info rule omits its target separator".to_owned())?;
        let mut token = String::new();
        let mut chars = rule[separator + 1..].chars().peekable();
        while let Some(ch) = chars.next() {
            if ch.is_whitespace() {
                if !token.is_empty() {
                    dependencies.push(std::mem::take(&mut token));
                }
                continue;
            }
            if ch != '\\' {
                token.push(ch);
                continue;
            }
            match chars.peek().copied() {
                Some(next) if next.is_whitespace() || matches!(next, '\\' | ':' | '#') => {
                    token.push(chars.next().expect("peeked escape exists"));
                }
                Some(_) => token.push('\\'),
                None => return Err("dep-info ends with an incomplete escape".to_owned()),
            }
        }
        if !token.is_empty() {
            dependencies.push(token);
        }
    }
    Ok(dependencies)
}

fn is_escaped(value: &str, index: usize) -> bool {
    value[..index]
        .chars()
        .rev()
        .take_while(|ch| *ch == '\\')
        .count()
        % 2
        == 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_spaces_continuations_colons_and_windows_paths() {
        let parsed = parse_makefile_dep_info(
            "out\\ file.wasm: src/main.rs src/with\\ space.rs \\\n             C:\\repo\\workflow\\tasks.rs escaped\\:colon.rs\nother: second.rs\n",
        )
        .unwrap();
        assert_eq!(
            parsed,
            [
                "src/main.rs",
                "src/with space.rs",
                "C:\\repo\\workflow\\tasks.rs",
                "escaped:colon.rs",
                "second.rs",
            ]
        );
    }
}
