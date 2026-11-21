//! Verdict type rendered by the egress fetch endpoint.

use serde::Serialize;

/// What happened to a fetch request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Body fetched, no rule matched.
    Fetched,
    /// Body fetched, at least one `record` rule matched.
    Recorded,
    /// Body withheld; a `refuse` rule matched.
    Blocked,
    /// The request could not be completed (DNS, connection, TLS, timeout).
    Failed,
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::Fetched => "fetched",
            Outcome::Recorded => "recorded",
            Outcome::Blocked => "blocked",
            Outcome::Failed => "failed",
        }
    }

    pub fn status_code(self) -> u16 {
        match self {
            Outcome::Fetched | Outcome::Recorded => 200,
            Outcome::Blocked => 403,
            Outcome::Failed => 502,
        }
    }
}

/// One fetch result. `body` is present only when the body was returned.
#[derive(Debug, Clone)]
pub struct Verdict {
    pub outcome: Outcome,
    pub rule_ids: Vec<&'static str>,
    pub message: Option<String>,
    pub body: Option<String>,
    pub content_type: Option<String>,
    pub bytes: usize,
    pub truncated: bool,
}

impl Verdict {
    pub fn fetched(body: String, content_type: Option<String>, bytes: usize) -> Self {
        Self {
            outcome: Outcome::Fetched,
            rule_ids: Vec::new(),
            message: None,
            body: Some(body),
            content_type,
            bytes,
            truncated: false,
        }
    }

    pub fn recorded(
        body: String,
        content_type: Option<String>,
        bytes: usize,
        rule_ids: Vec<&'static str>,
        message: String,
    ) -> Self {
        Self {
            outcome: Outcome::Recorded,
            rule_ids,
            message: Some(message),
            body: Some(body),
            content_type,
            bytes,
            truncated: false,
        }
    }

    pub fn blocked(
        rule_ids: Vec<&'static str>,
        message: String,
        bytes: usize,
        truncated: bool,
    ) -> Self {
        Self {
            outcome: Outcome::Blocked,
            rule_ids,
            message: Some(message),
            body: None,
            content_type: None,
            bytes,
            truncated,
        }
    }

    pub fn failed(message: String) -> Self {
        Self {
            outcome: Outcome::Failed,
            rule_ids: Vec::new(),
            message: Some(message),
            body: None,
            content_type: None,
            bytes: 0,
            truncated: false,
        }
    }

    /// JSON document returned to the caller.
    pub fn to_json(&self) -> String {
        #[derive(Serialize)]
        struct Json<'a> {
            outcome: &'a str,
            rule_ids: &'a [&'static str],
            bytes: usize,
            truncated: bool,
            as_of: String,
            #[serde(skip_serializing_if = "Option::is_none")]
            body: Option<&'a str>,
            #[serde(skip_serializing_if = "Option::is_none")]
            content_type: Option<&'a str>,
            #[serde(skip_serializing_if = "Option::is_none")]
            message: Option<&'a str>,
        }

        serde_json::to_string(&Json {
            outcome: self.outcome.as_str(),
            rule_ids: &self.rule_ids,
            bytes: self.bytes,
            truncated: self.truncated,
            as_of: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            body: self.body.as_deref(),
            content_type: self.content_type.as_deref(),
            message: self.message.as_deref(),
        })
        .unwrap_or_else(|_| {
            "{\"outcome\":\"failed\",\"rule_ids\":[],\"message\":\"serialisation failed\"}"
                .to_string()
        })
    }

    /// Headers mirroring the edge contract. `x-waf-rule-id` is the first rule
    /// in deterministic order; `x-waf-rule-ids` lists all of them.
    pub fn headers(&self) -> Vec<(&'static str, String)> {
        let mut headers = vec![("x-waf-verdict", self.outcome.as_str().to_string())];
        if let Some(first) = self.rule_ids.first() {
            headers.push(("x-waf-rule-id", (*first).to_string()));
            headers.push(("x-waf-rule-ids", self.rule_ids.join(",")));
        }
        headers
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocked_headers_name_the_first_rule() {
        let verdict = Verdict::blocked(
            vec!["EG-2001", "EG-2003"],
            "blocked by EG-2001: injection".to_string(),
            12,
            false,
        );
        let headers: std::collections::HashMap<_, _> = verdict.headers().into_iter().collect();
        assert_eq!(
            headers.get("x-waf-verdict").map(String::as_str),
            Some("blocked")
        );
        assert_eq!(
            headers.get("x-waf-rule-id").map(String::as_str),
            Some("EG-2001")
        );
        assert_eq!(
            headers.get("x-waf-rule-ids").map(String::as_str),
            Some("EG-2001,EG-2003")
        );
    }
}
