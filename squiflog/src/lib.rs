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
    structured_data: Option<String>,
    message: Option<String>,
}

impl Syslog {
    pub fn from_str(s: &str) -> Result<Self, Error> {
        // split syslog string into elements up to structured data and (message)
        let mut items = s.splitn(7," ");

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

        let sd_and_msg = items.next().ok_or("Missing structured data and/or message.")?;


        // should be no more after this
        assert!(items.next().is_none());

        // structured_data - check that next string is "-" or "["
        let mut structured_data: Option<String> = None;
        let mut structured_data_chars = sd_and_msg.char_indices();
        let mut message_idx = 2; // start after hyphen
        while let Some(item) = structured_data_chars.next() {
            match item {
                (0,'-') => {
                    // No structured_data
                    break;
                },
                (0,'[') => {
                    // Has structured data
                    continue;
                },
                (0, _) => {
                    Err("Invalid syslog format.")?
                },
                (idx,']') => {
                    if let Some((_, '[')) = structured_data_chars.next() {
                        // if there is more structured data, keep going
                        continue;
                    } else {
                        // else, end of structured data
                        // include the '[' and ']' in structured_data
                        structured_data = Some(sd_and_msg[..idx+1].to_string());
                        message_idx = idx+2;
                        break;
                    }
                },
                _ => {
                    continue;
                },
            }
        }

        let mut message: Option<String> = None;

        // check if there is a message
        let rest = sd_and_msg.get(message_idx..);
        if rest.is_some() {
            message = Some(rest.ok_or("Invalid message.")?.trim().to_string());
        }

        Ok(Syslog {
            priority,
            version: version.to_owned(),
            timestamp: timestamp.to_owned(),
            hostname: hostname.to_owned(),
            app_name: app_name.to_owned(),
            proc_id: proc_id.to_owned(),
            message_id: message_id.to_owned(),
            structured_data,
            message,
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
        // from docker alpine
        let input = "<30>1 2020-02-13T00:51:39.527825Z docker-desktop 8b1089798cf8 1481 8b1089798cf8 - hello world\n";

        let expected = Syslog {
            priority: Priority { facility: 3, severity: 6 },
            version: "1".to_owned(),
            timestamp: "2020-02-13T00:51:39.527825Z".to_owned(),
            hostname: "docker-desktop".to_owned(),
            app_name: "8b1089798cf8".to_owned(),
            proc_id: "1481".to_owned(),
            message_id: "8b1089798cf8".to_owned(),
            structured_data: None,
            message: Some("hello world".to_owned()),
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
    fn parse_rfc5424_syslog_specs_example_1() {
        // example 1 from https://tools.ietf.org/html/rfc5424
        let input = "<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - BOM’su root’ failed for lonvick on /dev/pts/8\n";

        let expected = Syslog {
            priority: Priority { facility: 4, severity: 2 },
            version: "1".to_owned(),
            timestamp: "2003-10-11T22:14:15.003Z".to_owned(),
            hostname: "mymachine.example.com".to_owned(),
            app_name: "su".to_owned(),
            proc_id: "-".to_owned(),
            message_id: "ID47".to_owned(),
            structured_data: None,
            message: Some("BOM’su root’ failed for lonvick on /dev/pts/8".to_owned()),
        };

        let actual = Syslog::from_str(input).expect("Could not parse input for syslog.");

        assert_eq!(expected, actual);
    }

    #[test]
    fn parse_rfc5424_syslog_specs_example_2() {
        // example 2 from https://tools.ietf.org/html/rfc5424
        let input = "<165>1 2003-08-24T05:14:15.000003-07:00 192.0.2.1 myproc 8710 - - %% It's time to make the do-nuts.\n";

        let expected = Syslog {
            priority: Priority { facility: 20, severity: 5 },
            version: "1".to_owned(),
            timestamp: "2003-08-24T05:14:15.000003-07:00".to_owned(),
            hostname: "192.0.2.1".to_owned(),
            app_name: "myproc".to_owned(),
            proc_id: "8710".to_owned(),
            message_id: "-".to_owned(),
            structured_data: None,
            message: Some("%% It's time to make the do-nuts.".to_owned()),
        };

        let actual = Syslog::from_str(input).expect("Could not parse input for syslog.");

        assert_eq!(expected, actual);
    }

    #[test]
    fn parse_rfc5424_syslog_specs_example_3() {
        // example 3 from https://tools.ietf.org/html/rfc5424
        let input = "<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut=\"3\" eventSource=\"Application\" eventID=\"1011\"] BOMAn application event log entry...\n";

        let expected = Syslog {
            priority: Priority { facility: 20, severity: 5 },
            version: "1".to_owned(),
            timestamp: "2003-10-11T22:14:15.003Z".to_owned(),
            hostname: "mymachine.example.com".to_owned(),
            app_name: "evntslog".to_owned(),
            proc_id: "-".to_owned(),
            message_id: "ID47".to_owned(),
            structured_data: Some("[exampleSDID@32473 iut=\"3\" eventSource=\"Application\" eventID=\"1011\"]".to_owned()),
            message: Some("BOMAn application event log entry...".to_owned()),
        };

        let actual = Syslog::from_str(input).expect("Could not parse input for syslog.");

        assert_eq!(expected, actual);
    }

    #[test]
    fn parse_rfc5424_syslog_specs_example_4() {
        // example 4 from https://tools.ietf.org/html/rfc5424

        let input = "<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut=\"3\" eventSource=\"Application\" eventID=\"1011\"][examplePriority@32473 class=\"high\"]";

        let expected = Syslog {
            priority: Priority { facility: 20, severity: 5 },
            version: "1".to_owned(),
            timestamp: "2003-10-11T22:14:15.003Z".to_owned(),
            hostname: "mymachine.example.com".to_owned(),
            app_name: "evntslog".to_owned(),
            proc_id: "-".to_owned(),
            message_id: "ID47".to_owned(),
            structured_data: Some("[exampleSDID@32473 iut=\"3\" eventSource=\"Application\" eventID=\"1011\"][examplePriority@32473 class=\"high\"]".to_owned()),
            message: None,
        };

        let actual = Syslog::from_str(input).expect("Could not parse input for syslog.");

        assert_eq!(expected, actual);
    }
}
