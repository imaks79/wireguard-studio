use rand::Rng;

/// WireGuard listen ports are frequently randomized within the IANA
/// dynamic/private port range to avoid an obviously "default" footprint.
pub const RANDOM_LISTEN_PORT_RANGE: (u16, u16) = (49152, 65535);

pub fn split_csv(text: &str) -> Vec<String> {
    text.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect()
}

pub fn split_lines(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect()
}

pub fn parse_int(text: &str, field_name: &str) -> Result<Option<i64>, String> {
    let text = text.trim();
    if text.is_empty() {
        return Ok(None);
    }
    text.parse::<i64>()
        .map(Some)
        .map_err(|_| format!("{field_name} must be a whole number, got {text:?}"))
}

pub fn parse_u32(text: &str, field_name: &str) -> Result<Option<u32>, String> {
    Ok(parse_int(text, field_name)?.map(|v| v.max(0) as u32))
}

pub fn generate_random_listen_port() -> u16 {
    rand::thread_rng().gen_range(RANDOM_LISTEN_PORT_RANGE.0..=RANDOM_LISTEN_PORT_RANGE.1)
}

/// Accepts a blank field (no port), a literal port number, or the word
/// "random" (case-insensitive), which picks a fresh port each time it's
/// resolved.
pub fn resolve_listen_port(text: &str) -> Result<Option<u16>, String> {
    let text = text.trim();
    if text.is_empty() {
        return Ok(None);
    }
    if text.eq_ignore_ascii_case("random") {
        return Ok(Some(generate_random_listen_port()));
    }
    text.parse::<u16>()
        .map(Some)
        .map_err(|_| format!("Listen Port must be a number or 'random', got {text:?}"))
}

pub fn random_tunnel_id() -> u32 {
    rand::thread_rng().gen_range(1..=65000)
}

/// Makes `name` safe to use as a file's base name (e.g. a suggested export
/// file name built from a free-text "client name" field): strips
/// characters invalid on common filesystems (`/ \ : * ? " < > |`) and
/// trims surrounding whitespace/dots. Returns `None` if nothing usable is
/// left, so the caller can fall back to some other default.
pub fn sanitize_filename_component(name: &str) -> Option<String> {
    let cleaned: String = name
        .trim()
        .chars()
        .map(|c| if r#"/\:*?"<>|"#.contains(c) { '_' } else { c })
        .collect();
    let cleaned = cleaned.trim().trim_matches('.').to_string();
    if cleaned.is_empty() {
        None
    } else {
        Some(cleaned)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_filename_component_strips_unsafe_characters() {
        assert_eq!(sanitize_filename_component("Vasya's laptop"), Some("Vasya's laptop".to_string()));
        assert_eq!(sanitize_filename_component("Front desk: router"), Some("Front desk_ router".to_string()));
        assert_eq!(sanitize_filename_component("a/b\\c:d*e?f\"g<h>i|j"), Some("a_b_c_d_e_f_g_h_i_j".to_string()));
        assert_eq!(sanitize_filename_component("  ..  "), None);
        assert_eq!(sanitize_filename_component(""), None);
    }
}
