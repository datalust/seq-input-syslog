pub type Error = Box<dyn std::error::Error>;

#[derive(Debug, Eq, PartialEq)]
pub struct Syslog {
    priority: Priority,
    version: String,
    timestamp: String,
    hostname: String,
    app_name: String,
    proc_id: String,
    message_id: String,
    message: String,
}

impl Syslog {
    pub fn from_str(s: &str) -> Result<Self, Error> {
        // split header from message
        let mut header_and_message = s.split(" - ");

        let mut header = header_and_message.next().expect("Invalid syslog format.");
        let message = header_and_message.next().expect("Invalid syslog format.").trim();

        // get priority, e.g. "<30>"
        let mut priority_chars = header.char_indices();

        assert_eq!(Some((0, '<')), priority_chars.next());

        let mut priority = None;
        while let Some(item) = priority_chars.next() {
            match item {
                (7, _) => panic!("Invalid syslog format."),
                (idx,'>') => {
                    priority = Some(&header[1..idx]);
                    header = &header[idx+1..]; // TODO: Check bounds
                    break;
                },
                _ => continue,
            }
        }
        let priority: usize = priority.expect("Invalid syslog format.").parse().expect("Priority is not a valid number");

        let priority = Priority::from_raw(priority);

        // get remaining header items
        let mut header_items = header.split_whitespace();

        let version = header_items.next().expect("Missing version.");
        let timestamp = header_items.next().expect("Missing timestamp.");
        let hostname = header_items.next().expect("Missing hostname.");
        let app_name = header_items.next().expect("Missing app_name.");
        let proc_id = header_items.next().expect("Missing proc_id.");
        let message_id = header_items.next().expect("Missing message_id.");

        Ok(Syslog {
            priority,
            version: version.to_owned(),
            timestamp: timestamp.to_owned(),
            hostname: hostname.to_owned(),
            app_name: app_name.to_owned(),
            proc_id: proc_id.to_owned(),
            message_id: message_id.to_owned(),
            message: message.to_owned(),
        })
    }
}

#[derive(Debug, Eq, PartialEq)]
struct Priority {
    facility: usize,
    severity: usize,
}

impl Priority {
    fn from_raw(raw: usize) -> Self {
        let facility = raw / 8;
        let severity = raw % 8;

        Priority { facility, severity }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_rfc5424_syslog_message() {
        let input = "<30>1 2020-02-13T00:51:39.527825Z docker-desktop 8b1089798cf8 1481 8b1089798cf8 - hello world\n";

        let expected = Syslog {
            priority: Priority { facility: 3, severity: 6 },
            version: "1".to_owned(),
            timestamp: "2020-02-13T00:51:39.527825Z".to_owned(),
            hostname: "docker-desktop".to_owned(),
            app_name: "8b1089798cf8".to_owned(),
            proc_id: "1481".to_owned(),
            message_id: "8b1089798cf8".to_owned(),
            message: "hello world".to_owned(),
        };

        let actual = Syslog::from_str(input).expect("Could not parse input for syslog.");

        assert_eq!(expected, actual);
    }
}
