use crate::error::{err_msg, Error};
use std::collections::HashMap;

#[derive(Debug, Eq, PartialEq)]
pub struct Priority {
    pub facility: usize,
    pub severity: usize,
}

impl Priority {
    fn from_raw(raw: usize) -> Self {
        let facility = raw / 8;
        let severity = raw % 8;

        Priority { facility, severity }
    }

    pub fn severity(&self) -> &str {
        match self.severity {
            0 => "emerg",
            1 => "alert",
            2 => "crit",
            3 => "err",
            4 => "warning",
            5 => "notice",
            6 => "info",
            _ => "debug",
        }
    }

    pub fn facility(&self) -> &str {
        match self.facility {
            0 => "kern",
            1 => "user",
            2 => "mail",
            3 => "daemon",
            4 => "auth",
            5 => "syslog",
            6 => "lpr",
            7 => "news",
            8 => "uucp",
            9 => "cron",
            10 => "authpriv",
            11 => "ftp",
            12 => "ntp",
            13 => "security",
            14 => "console",
            15 => "solaris-cron",
            16 => "local0",
            17 => "local1",
            18 => "local2",
            19 => "local3",
            20 => "local4",
            21 => "local5",
            22 => "local6",
            23 => "local7",
            _ => "unknown",
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct StructuredDataElement<'a> {
    pub id: &'a str,
    pub param: HashMap<&'a str, &'a str>,
}

impl<'a> StructuredDataElement<'a> {
    fn from_str(s: &'a str) -> Result<Self, Error> {
        let mut items = s.split(" ");

        let id = items.next().expect("incorrect structured data format");

        let mut param_list = HashMap::<&'a str, &'a str>::new();

        while let Some(param) = items.next() {
            let mut param_items = param.split("=");
            let param_name = param_items
                .next()
                .expect("incorrect structured data format - no param name");
            let param_value = param_items
                .next()
                .expect("incorrect structured data format - no param value");
            let param_value = param_value.trim_matches('\"');
            param_list.insert(param_name, param_value);
        }

        Ok(StructuredDataElement {
            id,
            param: param_list,
        })
    }
}

struct StructuredDataList {}

impl StructuredDataList {
    fn from_str(s: &str) -> Result<Vec<StructuredDataElement>, Error> {
        let len = s.len();
        let s = &s[1..len - 2]; // remove starting and trailing '[' and ']'

        let mut s = s.split("]["); // split on separators

        let mut list = vec![];

        while let Some(sd_element) = s.next() {
            list.push(StructuredDataElement::from_str(sd_element).expect("NOPE"));
        }

        Ok(list)
    }
}

fn filter_nil(s: &str) -> Option<&str> {
    match s {
        "-" => None,
        _ => Some(s),
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct Message<'a> {
    pub priority: Priority,
    pub version: i32,
    pub timestamp: Option<&'a str>,
    pub hostname: Option<&'a str>,
    pub app_name: Option<&'a str>,
    pub proc_id: Option<&'a str>,
    pub message_id: Option<&'a str>,
    // pub structured_data: Option<&'a str>,
    pub structured_data: Option<Vec<StructuredDataElement<'a>>>,
    pub message: Option<&'a str>,
}

/**
A SYSLOG message

RFC5424 format:
<PRIVAL>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA (MSG)

PRIVAL - a number from 0..191
VERSION - always 1 for RFC5424
STRUCTURED-DATA - [SDID PARAM-NAME="PARAM-VALUE"][SDID2 PARAM2-NAME="PARAM2-VALUE" PARAM3-NAME="PARAM3-VALUE"]
MSG - message is optional, and can contain spaces

All other values are alphanumeric strings with no spaces.
See https://tools.ietf.org/html/rfc5424#section-5.1 for details.
*/
impl<'a> Message<'a> {
    pub fn from_str(s: &'a str) -> Result<Self, Error> {
        // split syslog string into elements up to structured data and (message)
        let mut items = s.splitn(7, " ");

        // get priority, e.g. "<30>"
        let pri_version = items.next().expect("empty syslog message");
        let mut priority_chars = pri_version.char_indices();

        assert_eq!(Some((0, '<')), priority_chars.next());

        let mut priority = None;
        let mut version = None;
        while let Some(item) = priority_chars.next() {
            match item {
                (7, _) => Err(err_msg("invalid syslog priority - too long"))?, // priority format: <1234>
                (idx, '>') => {
                    priority = Some(&pri_version[1..idx]);
                    version = Some(
                        pri_version
                            .get(idx + 1..)
                            .ok_or_else(|| err_msg("unexpected end of syslog header"))?,
                    );
                    break;
                }
                _ => continue,
            }
        }
        let priority = priority
            .ok_or_else(|| err_msg("invalid syslog priority - not a number"))?
            .parse::<usize>()
            .map_err(Error::from)?;
        let priority = Priority::from_raw(priority);

        let version = version
            .ok_or_else(|| err_msg("invalid syslog version"))?
            .parse::<i32>()
            .unwrap();

        // get remaining header items

        let timestamp = Some(
            items
                .next()
                .ok_or_else(|| err_msg("missing syslog timestamp"))?,
        )
        .and_then(filter_nil);
        let hostname = Some(
            items
                .next()
                .ok_or_else(|| err_msg("missing syslog hostname"))?,
        )
        .and_then(filter_nil);
        let app_name = Some(
            items
                .next()
                .ok_or_else(|| err_msg("missing syslog app_name"))?,
        )
        .and_then(filter_nil);
        let proc_id = Some(
            items
                .next()
                .ok_or_else(|| err_msg("missing syslog proc_id"))?,
        )
        .and_then(filter_nil);
        let message_id = Some(
            items
                .next()
                .ok_or_else(|| err_msg("missing syslog message_id"))?,
        )
        .and_then(filter_nil);

        let sd_and_msg = items
            .next()
            .ok_or_else(|| err_msg("missing structured data and/or message"))?;

        // should be no more after this TODO: Turn into error
        assert!(items.next().is_none());

        // structured_data - check that next string is "-" or "["
        let mut structured_data: Option<Vec<StructuredDataElement>> = None;
        let mut structured_data_chars = sd_and_msg.char_indices();
        let mut message_idx = 2; // start after hyphen
        while let Some(item) = structured_data_chars.next() {
            match item {
                (0, '-') => {
                    // No structured data
                    break;
                }
                (0, '[') => {
                    // Has structured data
                    continue;
                }
                (0, _) => Err(err_msg(
                    "invalid syslog structured data format - no leading '['",
                ))?,
                (idx, ']') => {
                    if let Some((_, '[')) = structured_data_chars.next() {
                        // if there is more structured data, keep going
                        continue;
                    } else {
                        // else, end of structured data
                        // include the '[' and ']' in structured_data
                        // structured_data = Some(&sd_and_msg[..idx + 1]);
                        structured_data = Some(
                            StructuredDataList::from_str(&sd_and_msg[..idx + 1]).expect("NOPE"),
                        );
                        message_idx = idx + 2;
                        break;
                    }
                }
                _ => {
                    continue;
                }
            }
        }

        let mut message: Option<&str> = None;

        // check if there is a message
        let rest = sd_and_msg.get(message_idx..);
        if rest.is_some() {
            message = Some(
                rest.ok_or_else(|| err_msg("invalid syslog message"))?
                    .trim(),
            );
        }

        Ok(Message {
            priority,
            version,
            timestamp,
            hostname,
            app_name,
            proc_id,
            message_id,
            structured_data,
            message,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_rfc5424_syslog_message() {
        // from docker alpine
        let input = "<30>1 2020-02-13T00:51:39.527825Z docker-desktop 8b1089798cf8 1481 8b1089798cf8 - hello world\n";

        let expected = Message {
            priority: Priority {
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

        let actual = Message::from_str(input).expect("could not parse input for syslog");

        assert_eq!(expected, actual);
    }

    #[test]
    fn parse_rfc5424_syslog_should_throw_error() {
        let input = "<30>1 2020-02-13T00:51:39\n";

        let actual = Message::from_str(input);

        assert_eq!("missing syslog hostname", actual.unwrap_err().to_string());
    }

    #[test]
    fn parse_rfc5424_syslog_specs_example_1() {
        // example 1 from https://tools.ietf.org/html/rfc5424
        let input = "<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - BOM’su root’ failed for lonvick on /dev/pts/8\n";

        let expected = Message {
            priority: Priority {
                facility: 4,
                severity: 2,
            },
            version: 1,
            timestamp: Some("2003-10-11T22:14:15.003Z"),
            hostname: Some("mymachine.example.com"),
            app_name: Some("su"),
            proc_id: None,
            message_id: Some("ID47"),
            structured_data: None,
            message: Some("BOM’su root’ failed for lonvick on /dev/pts/8"),
        };

        let actual = Message::from_str(input).expect("could not parse input for syslog");

        assert_eq!(expected, actual);
    }

    #[test]
    fn parse_rfc5424_syslog_specs_example_2() {
        // example 2 from https://tools.ietf.org/html/rfc5424
        let input = "<165>1 2003-08-24T05:14:15.000003-07:00 192.0.2.1 myproc 8710 - - %% It's time to make the do-nuts.\n";

        let expected = Message {
            priority: Priority {
                facility: 20,
                severity: 5,
            },
            version: 1,
            timestamp: Some("2003-08-24T05:14:15.000003-07:00"),
            hostname: Some("192.0.2.1"),
            app_name: Some("myproc"),
            proc_id: Some("8710"),
            message_id: None,
            structured_data: None,
            message: Some("%% It's time to make the do-nuts."),
        };

        let actual = Message::from_str(input).expect("could not parse input for syslog");

        assert_eq!(expected, actual);
    }

    #[test]
    fn parse_rfc5424_syslog_specs_example_3() {
        // example 3 from https://tools.ietf.org/html/rfc5424
        let input = "<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut=\"3\" eventSource=\"Application\" eventID=\"1011\"] BOMAn application event log entry...\n";

        let mut sd_params = HashMap::new();
        sd_params.insert("iut", "3");
        sd_params.insert("eventSource", "Application");
        sd_params.insert("eventID", "1011");

        let expected = Message {
            priority: Priority {
                facility: 20,
                severity: 5,
            },
            version: 1,
            timestamp: Some("2003-10-11T22:14:15.003Z"),
            hostname: Some("mymachine.example.com"),
            app_name: Some("evntslog"),
            proc_id: None,
            message_id: Some("ID47"),
            structured_data: Some(vec![StructuredDataElement {
                id: "exampleSDID@32473",
                param: sd_params,
            }]),
            message: Some("BOMAn application event log entry..."),
        };

        let actual = Message::from_str(input).expect("could not parse input for syslog");

        assert_eq!(expected, actual);
    }

    #[test]
    fn parse_rfc5424_syslog_specs_example_4() {
        // example 4 from https://tools.ietf.org/html/rfc5424

        let input = "<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut=\"3\" eventSource=\"Application\" eventID=\"1011\"][examplePriority@32473 class=\"high\"]";

        let mut sd_params = HashMap::new();
        sd_params.insert("iut", "3");
        sd_params.insert("eventSource", "Application");
        sd_params.insert("eventID", "1011");

        let mut sd_params2 = HashMap::new();
        sd_params2.insert("class", "high");

        let sd = vec![
            StructuredDataElement {
                id: "exampleSDID@32473",
                param: sd_params,
            },
            StructuredDataElement {
                id: "examplePriority@32473",
                param: sd_params2,
            },
        ];

        let expected = Message {
            priority: Priority {
                facility: 20,
                severity: 5,
            },
            version: 1,
            timestamp: Some("2003-10-11T22:14:15.003Z"),
            hostname: Some("mymachine.example.com"),
            app_name: Some("evntslog"),
            proc_id: None,
            message_id: Some("ID47"),
            structured_data: Some(sd),
            message: None,
        };

        let actual = Message::from_str(input).expect("could not parse input for syslog");

        assert_eq!(expected, actual);
    }

    #[test]
    fn parse_rfc5424_empty_valid_syslog() {
        let input = "<0>0 - - - - - -";

        let expected = Message {
            priority: Priority {
                facility: 0,
                severity: 0,
            },
            version: 0,
            timestamp: None,
            hostname: None,
            app_name: None,
            proc_id: None,
            message_id: None,
            structured_data: None,
            message: None,
        };

        let actual = Message::from_str(input).expect("could not parse input for syslog");

        assert_eq!(expected, actual);
    }

    #[test]
    fn structured_data_param_from_string() {
        let input = "exampleSDID@32473 iut=\"3\" eventSource=\"Application\" eventID=\"1011\"";

        let mut sd_params = HashMap::new();
        sd_params.insert("iut", "3");
        sd_params.insert("eventSource", "Application");
        sd_params.insert("eventID", "1011");

        let expected = StructuredDataElement {
            id: "exampleSDID@32473",
            param: sd_params,
        };

        let actual = StructuredDataElement::from_str(input)
            .expect("could not parse input for structured data element");

        assert_eq!(expected, actual);
    }
}
