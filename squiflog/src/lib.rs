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
    structured_data: String,
    message: String,
}

impl Syslog {
    pub fn from_str(s: &str) -> Result<Self, Error> {
        // split syslog string into elements
        let mut items = s.splitn(8," ");

        // get priority, e.g. "<30>"
        let pri_version = items.next().expect("Invalid syslog message.");
        let mut priority_chars = pri_version.char_indices();

        assert_eq!(Some((0, '<')), priority_chars.next());

        let mut priority = None;
        let mut version = None;
        while let Some(item) = priority_chars.next() {
            match item {
                (7, _) => Err("Invalid syslog format.")?,
                (idx,'>') => {
                    priority = Some(&pri_version[1..idx]);
                    version = Some(pri_version.get(idx+1..).ok_or("Unexpected end of header.")?);
                    break;
                },
                _ => continue,
            }
        }
        let priority = priority.ok_or("Invalid syslog format.")?.parse::<usize>().map_err(Error::from)?;
        let priority = Priority::from_raw(priority);

        let version = version.ok_or("Invalid syslog format. Invalid version.")?;

        // get remaining header items

        let timestamp = items.next().ok_or("Missing timestamp.")?;
        let hostname = items.next().ok_or("Missing hostname.")?;
        let app_name = items.next().ok_or("Missing app_name.")?;
        let proc_id = items.next().ok_or("Missing proc_id.")?;
        let message_id = items.next().ok_or("Missing message_id.")?;
        let structured_data = items.next().ok_or("Missing structured data.")?;
        let message = items.next().ok_or("Missing message.")?.trim();

        assert!(items.next().is_none());

        Ok(Syslog {
            priority,
            version: version.to_owned(),
            timestamp: timestamp.to_owned(),
            hostname: hostname.to_owned(),
            app_name: app_name.to_owned(),
            proc_id: proc_id.to_owned(),
            message_id: message_id.to_owned(),
            structured_data: structured_data.to_owned(),
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
            structured_data: "-".to_owned(),
            message: "hello world".to_owned(),
        };

        let actual = Syslog::from_str(input).expect("Could not parse input for syslog.");

        assert_eq!(expected, actual);
    }

    #[test]
    fn parse_rfc5424_syslog_should_throw_error() {
        let input = "<30>1 2020-02-13T00:51:39\n";

        let actual = Syslog::from_str(input);

        assert_eq!("Missing hostname.", actual.unwrap_err().to_string());
    }

    #[test]
    fn parse_rfc5424_syslog_message_with_message_containing_hyphen() {
        let input = "<30>1 2020-02-13T00:51:39.527825Z docker-desktop 8b1089798cf8 1481 8b1089798cf8 - hello world - oh hey there's more\n";

        let expected = Syslog {
            priority: Priority { facility: 3, severity: 6 },
            version: "1".to_owned(),
            timestamp: "2020-02-13T00:51:39.527825Z".to_owned(),
            hostname: "docker-desktop".to_owned(),
            app_name: "8b1089798cf8".to_owned(),
            proc_id: "1481".to_owned(),
            message_id: "8b1089798cf8".to_owned(),
            structured_data: "-".to_owned(),
            message: "hello world - oh hey there's more".to_owned(),
        };

        let actual = Syslog::from_str(input).expect("Could not parse input for syslog.");

        assert_eq!(expected, actual);
    }

    #[test]
    fn parse_rfc5424_syslog_message_from_syslog_unknown_proc_id() {
        let input = "<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - BOM’su root’ failed for lonvick on /dev/pts/8\n";

        let expected = Syslog {
            priority: Priority { facility: 4, severity: 2 },
            version: "1".to_owned(),
            timestamp: "2003-10-11T22:14:15.003Z".to_owned(),
            hostname: "mymachine.example.com".to_owned(),
            app_name: "su".to_owned(),
            proc_id: "-".to_owned(),
            message_id: "ID47".to_owned(),
            structured_data: "-".to_owned(),
            message: "BOM’su root’ failed for lonvick on /dev/pts/8".to_owned(),
        };

        let actual = Syslog::from_str(input).expect("Could not parse input for syslog.");

        assert_eq!(expected, actual);
    }
}
