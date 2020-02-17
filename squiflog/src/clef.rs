use std::{
    collections::HashMap,
};

use serde_json::Value;

#[derive(Debug, Serialize, Deserialize)]
pub struct Message {
    #[serde(rename = "@t")]
    pub timestamp: Option<String>,

    #[serde(rename = "@l")]
    pub level: Option<String>,

    #[serde(rename = "@m")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,

    #[serde(rename = "@mt")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_template: Option<String>,

    // This is mapped from `full_message`, which GELF suggests might contain a backtrace
    #[serde(rename = "@x")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exception: Option<String>,

    // @i and @r are currently not implemented

    // Everything else
    #[serde(flatten)]
    pub additional: HashMap<String, Value>,
}