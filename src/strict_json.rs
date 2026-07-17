//! Strict UTF-8 JSON parsing with duplicate-member rejection.

use std::fmt;
use std::str::Utf8Error;

use serde::de::{DeserializeSeed, Error as _, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use thiserror::Error;

/// Strict JSON parsing failure.
#[derive(Debug, Error)]
pub enum StrictJsonError {
    /// Input was not valid UTF-8.
    #[error("JSON input is not valid UTF-8: {0}")]
    InvalidUtf8(#[from] Utf8Error),
    /// Input was not one complete duplicate-free JSON value.
    #[error("invalid strict JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),
}

/// Parse exactly one UTF-8 JSON value and reject duplicate object members.
///
/// # Errors
///
/// Returns [`StrictJsonError`] for invalid UTF-8, duplicate keys, malformed JSON, or trailing data.
pub fn parse_strict_json(input: &[u8]) -> Result<Value, StrictJsonError> {
    let text = std::str::from_utf8(input)?;
    let mut deserializer = serde_json::Deserializer::from_str(text);
    let value = StrictValueSeed.deserialize(&mut deserializer)?;
    deserializer.end()?;
    Ok(value)
}

struct StrictValueSeed;

impl<'de> DeserializeSeed<'de> for StrictValueSeed {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictValueVisitor)
    }
}

struct StrictValueVisitor;

impl<'de> Visitor<'de> for StrictValueVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a strict JSON value")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("JSON number is not finite"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_string(value.to_owned())
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(Value::String(value))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(StrictValueSeed)? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(A::Error::custom(format!("duplicate object member `{key}`")));
            }
            let value = map.next_value_seed(StrictValueSeed)?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}

#[cfg(test)]
mod tests {
    use super::parse_strict_json;

    #[test]
    fn rejects_duplicate_members_at_any_depth() {
        assert!(parse_strict_json(br#"{"a":1,"a":2}"#).is_err());
        assert!(parse_strict_json(br#"{"a":{"b":1,"b":2}}"#).is_err());
    }

    #[test]
    fn rejects_invalid_utf8_and_trailing_data() {
        assert!(parse_strict_json(&[b'"', 0xff, b'"']).is_err());
        assert!(parse_strict_json(br"{} true").is_err());
    }

    #[test]
    fn preserves_one_complete_value() {
        let value = parse_strict_json(br#"{"a":[1,true,null]}"#).expect("valid JSON");
        assert_eq!(value["a"][0], 1);
    }
}
