use serde_json::Value;

/// Canonical JSON serialization according to Pactum V0 spec:
/// 1. UTF-8 encoding
/// 2. Keys sorted lexicographically (byte-order of UTF-8 codepoints)
/// 3. No insignificant whitespace
/// 4. No floating point numbers (all numbers are decimal strings)
/// 5. Arrays preserve order
/// 6. Booleans are true/false, null is null
pub fn canonical_string(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => {
            // In Pactum V0, all numbers should be strings, but handle numbers for robustness
            if n.is_u64() {
                n.as_u64().unwrap().to_string()
            } else if n.is_i64() {
                n.as_i64().unwrap().to_string()
            } else {
                panic!("Floating point numbers not allowed in Pactum V0 canonical JSON");
            }
        }
        Value::String(s) => {
            // Escape JSON string properly
            let mut result = String::with_capacity(s.len() + 2);
            result.push('"');
            for ch in s.chars() {
                match ch {
                    '"' => result.push_str("\\\""),
                    '\\' => result.push_str("\\\\"),
                    '\n' => result.push_str("\\n"),
                    '\r' => result.push_str("\\r"),
                    '\t' => result.push_str("\\t"),
                    '\u{0000}'..='\u{001F}' => {
                        result.push_str(&format!("\\u{:04x}", ch as u32));
                    }
                    _ => result.push(ch),
                }
            }
            result.push('"');
            result
        }
        Value::Array(arr) => {
            let mut result = String::new();
            result.push('[');
            for (i, item) in arr.iter().enumerate() {
                if i > 0 {
                    result.push(',');
                }
                result.push_str(&canonical_string(item));
            }
            result.push(']');
            result
        }
        Value::Object(obj) => {
            let mut entries: Vec<(&String, &Value)> = obj.iter().collect();
            // Sort keys lexicographically by UTF-8 byte order
            entries.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));

            let mut result = String::new();
            result.push('{');
            for (i, (key, value)) in entries.iter().enumerate() {
                if i > 0 {
                    result.push(',');
                }
                result.push_str(&canonical_string(&Value::String(key.to_string())));
                result.push(':');
                result.push_str(&canonical_string(value));
            }
            result.push('}');
            result
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_canonical_string() {
        let obj = json!({
            "z": "last",
            "a": "first",
            "m": {"nested": true}
        });
        let canon = canonical_string(&obj);
        assert_eq!(canon, r#"{"a":"first","m":{"nested":true},"z":"last"}"#);
    }

    #[test]
    fn test_array_order() {
        let arr = json!([3, 1, 2]);
        let canon = canonical_string(&arr);
        assert_eq!(canon, "[3,1,2]");
    }
}
