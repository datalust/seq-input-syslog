use std::collections::HashMap;

use serde_json::Value;

#[derive(Debug, Serialize, Deserialize)]
pub struct Message<'a> {
    #[serde(rename = "@t")]
    pub timestamp: Option<&'a str>,

    #[serde(rename = "@l")]
    pub level: Option<&'a str>,

    #[serde(rename = "@m")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<&'a str>,

    #[serde(rename = "@mt")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_template: Option<&'a str>,

    // This is mapped from `full_message`, which GELF suggests might contain a backtrace
    #[serde(rename = "@x")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exception: Option<&'a str>,

    // @i and @r are currently not implemented

    // Everything else
    #[serde(flatten)]
    pub additional: HashMap<&'a str, Value>,
}
