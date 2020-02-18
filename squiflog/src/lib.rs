#[macro_use]
extern crate serde_derive;

use std::collections::HashMap;

pub type Error = Box<dyn std::error::Error>;

mod clef;
mod syslog;

impl<'a> syslog::Message<'a> {
    fn to_clef(&self) -> clef::Message {
        //        #![deny(unused_variables)]

        let syslog::Message {
            priority,
            version,
            timestamp,
            hostname,
            app_name,
            proc_id,
            message_id,
            structured_data,
            message,
        } = self;

        let mut additional = HashMap::new();
        //
        //        additional.insert("version", version.to_string());
        //        if let Some(hostname) = hostname {
        //            additional.insert("hostname", hostname);
        //        }
        //        if let Some(app_name) = app_name {
        //            additional.insert("app_name", app_name);
        //        }
        //        if let Some(proc_id) = proc_id {
        //            additional.insert("proc_id", proc_id);
        //        }
        //        if let Some(message_id) = message_id {
        //            additional.insert("message_id", message_id);
        //        }
        //        if let Some(structured_data) = structured_data {
        //            additional.insert("structured_data", structured_data);
        //        }

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
            "@l": "Informational",
            "@m": "hello world",
            "@t": "2020-02-13T00:51:39.527825Z",
            "hostname": "docker-desktop",
            "app_name": "8b1089798cf8",
            "proc_id": "1481",
            "message_id": "8b1089798cf8",
            "version": 1,
        });

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
            structured_data: None,
            message: Some("hello world"),
        };

        let clef = syslog.to_clef();
        let actual = serde_json::to_value(clef).unwrap();

        assert_eq!(expected, actual);
    }
}
