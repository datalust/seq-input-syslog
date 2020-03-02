use std::{collections::HashMap, io, str};

use serde_json::{self, json};

use crate::error::Error;
use std::io::Write;

mod clef;
pub mod syslog;

metrics! {
    msg
}

/**
Configuration for CLEF formatting.
*/
#[derive(Debug, Clone)]
pub struct Config {}

impl Default for Config {
    fn default() -> Self {
        Config {}
    }
}

/**
Build a CLEF processor to handle messages.
*/
pub fn build(config: Config) -> Data {
    Data::new(config)
}

#[derive(Clone)]
pub struct Data {}

impl Data {
    pub fn new(_: Config) -> Self {
        Data {}
    }

    pub fn read_as_clef(&self, msg: &[u8]) -> Result<(), Error> {
        increment!(data.msg);
        let syslog = syslog::Message::from_bytes(msg)?;
        let clef = syslog.to_clef();
        let stdout = io::stdout();
        let mut stdout = stdout.lock();

        serde_json::to_writer(&mut stdout, &clef)?;
        stdout.write_all(b"\n")?;

        Ok(())
    }
}

impl<'a> syslog::Message<'a> {
    /**
    Covert a SYSLOG message into CLEF.

    The contents of the SYSLOG message is inspected and deserialized as CLEF-encoded
    JSON if possible. In this case, timestamp, message, and level information from
    the embedded CLEF is given precedence over the SYSLOG header.

    Other fields with conflicting names are prioritized:

      SYSLOG header > SYSLOG structured data > SYSLOG message embedded CLEF/JSON

    This means fields set by the system/on the logger are preferred over
    the fields attached to any one event.

    If fields conflict, then the lower-priority field is included with a
    double-underscore-prefixed name, e.g.: "__host".
    */
    pub fn to_clef(&self) -> clef::Message {
        #![deny(unused_variables)]

        let syslog::Message {
            priority,
            timestamp,
            hostname,
            app_name,
            proc_id,
            message_id,
            structured_data,
            message,
        } = self;

        let mut additional = HashMap::new();

        additional.insert("facility", json!(priority.facility()));
        if let Some(hostname) = hostname {
            additional.insert("hostname", json!(hostname));
        }
        if let Some(app_name) = app_name {
            additional.insert("app_name", json!(app_name));
        }
        if let Some(proc_id) = proc_id {
            additional.insert("proc_id", json!(proc_id));
        }
        if let Some(message_id) = message_id {
            additional.insert("message_id", json!(message_id));
        }

        if let Some(sd) = structured_data {
            for element in sd {
                additional.insert(element.id, json!(element.param));
            }
        }

        clef::Message {
            timestamp: *timestamp,
            level: Some(priority.severity()),
            message: *message,
            message_template: None,
            exception: None,
            additional,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use serde_json::{self, json};

    #[test]
    fn syslog_to_clef() {
        let expected = json!({
            "@l": "info",
            "@m": "hello world",
            "@t": "2020-02-13T00:51:39.527825Z",
            "facility": "daemon",
            "hostname": "docker-desktop",
            "app_name": "8b1089798cf8",
            "proc_id": "1481",
            "message_id": "8b1089798cf8",
        });

        let message = "hello world";

        let syslog = syslog::Message {
            priority: syslog::Priority {
                facility: 3,
                severity: 6,
            },
            timestamp: Some("2020-02-13T00:51:39.527825Z"),
            hostname: Some("docker-desktop"),
            app_name: Some("8b1089798cf8"),
            proc_id: Some("1481"),
            message_id: Some("8b1089798cf8"),
            structured_data: None,
            message: Some(message),
        };

        let clef = syslog.to_clef();
        let actual = serde_json::to_value(clef).unwrap();

        assert_eq!(expected, actual);
    }

    #[test]
    fn syslog_to_clef__with_structured_data() {
        let expected = json!({
            "@l": "info",
            "@m": "hello world",
            "@t": "2020-02-13T00:51:39.527825Z",
            "facility": "daemon",
            "version": 1,
            "hostname": "docker-desktop",
            "app_name": "8b1089798cf8",
            "proc_id": "1481",
            "message_id": "8b1089798cf8",
            "sdid1234": { "hello": "world", "event": "value" }
        });

        let message = "hello world";

        let mut sd_params = HashMap::new();
        sd_params.insert("hello", "world");
        sd_params.insert("event", "value");

        let syslog = syslog::Message {
            priority: syslog::Priority {
                facility: 3,
                severity: 6,
            },
            version: 1,
            timestamp: Some("2020-02-13T00:51:39.527825Z"),
            hostname: Some("docker-desktop"),
            app_name: Some("8b1089798cf8"),
            proc_id: Some("1481"),
            message_id: Some("8b1089798cf8"),
            structured_data: Some(vec![syslog::StructuredDataElement {
                id: "sdid1234",
                param: sd_params,
            }]),
            message: Some(message),
        };

        let clef = syslog.to_clef();
        let actual = serde_json::to_value(clef).unwrap();

        assert_eq!(expected, actual);
    }
}
