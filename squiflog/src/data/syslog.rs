use crate::error::{err_msg, Error};
use std::{collections::HashMap, borrow::Cow};
use chrono::Utc;

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

    pub fn severity(&self) -> &'static str {
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

    pub fn facility(&self) -> &'static str {
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

fn filter_nil(s: &[u8]) -> Option<&[u8]> {
    match s {
        b"-" => None,
        _ => Some(s),
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct Message<'a> {
    pub priority: Priority,
    pub timestamp: Option<&'a str>,
    pub hostname: Option<&'a str>,
    pub app_name: Option<&'a str>,
    pub proc_id: Option<&'a str>,
    pub message_id: Option<&'a str>,
    pub structured_data: Option<Vec<StructuredDataElement<'a>>>,
    pub message: Option<Cow<'a, str>>,
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
    pub fn from_str(s: &'a str) -> Self {
        Self::from_bytes(s.as_bytes())
    }

    pub fn from_bytes(s: &'a [u8]) -> Self {
        Self::from_rfc5424_bytes(s).unwrap_or_else(|_| Self::from_rfc3164_bytes(s))
    }

    pub fn from_rfc3164_bytes(s: &'a [u8]) -> Self {
        Message {
            priority: Priority::from_raw(13),
            timestamp: None,
            hostname: None,
            app_name: None,
            proc_id: None,
            message_id: None,
            structured_data: None,
            message: Some(String::from_utf8_lossy(s)),
        }
    }

    pub fn from_rfc5424_bytes(s: &'a [u8]) -> Result<Self, Error> {
        // split syslog string into elements up to structured data and (message)
        let mut items = s.splitn(7, |b| *b == 32u8); // split on spaces

        // get priority, e.g. "<30>"
        let pri_version = items.next().ok_or_else(|| err_msg("empty syslog message"))?;
        let mut priority_chars = pri_version.iter();

        if priority_chars.next() != Some(&b'<') {
            return Err(err_msg("invalid message, no <"))
        }

        let mut priority = None;
        let mut version = None;
        let mut idx = 1;
        while let Some(item) = priority_chars.next() {
            match item {
                b'>' => {
                    priority = Some(&pri_version[1..idx]);
                    version = Some(
                        pri_version
                            .get(idx + 1..)
                            .ok_or_else(|| err_msg("unexpected end of syslog header"))?,
                    );
                    break;
                }
                _ => idx += 1,
            }
        }

        if version != Some(&b"1"[..]) {
            return Err(err_msg("invalid message, version not 1"));
        }

        let priority_bytes = priority
            .ok_or_else(|| err_msg("invalid syslog priority - not a number"))?;

        if priority_bytes.len() > 4 {
            return Err(err_msg("invalid message, priority too long"));
        }

        let priority = std::str::from_utf8(&priority_bytes)?
            .parse::<usize>()
            .map_err(Error::from)?;

        let priority = Priority::from_raw(priority);

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

        // Should be no more after this because splitn limits the number of possible fragments
        assert!(items.next().is_none());

        // structured_data - check that next string is "-" or "["
        let mut structured_data: Option<Vec<StructuredDataElement>> = None;
        let mut structured_data_chars = sd_and_msg.iter();
        let mut message_idx = 2; // start after hyphen
        let mut idx = 0;
        while let Some(item) = structured_data_chars.next() {
            match (idx, item) {
                (0, b'-') => {
                    // No structured data
                    break;
                }
                (0, b'[') => {
                    // Has structured data
                    idx += 1;
                    continue;
                }
                (0, _) => Err(err_msg(
                    "invalid syslog structured data format - no leading '['",
                ))?,
                (ii, b']') => {
                    let following = structured_data_chars.next();
                    if let Some(b'[') = following {
                        // if there is more structured data, keep going
                        idx += 2;
                        continue;
                    } else {
                        // else, end of structured data
                        // include the '[' and ']' in structured_data
                        structured_data = Some(
                            StructuredDataList::from_str(std::str::from_utf8(&sd_and_msg[..ii + 1])?)?,
                        );
                        message_idx = ii + if following.is_some() { 2 } else { 1 };
                        break;
                    }
                }
                _ => {
                    idx += 1;
                    continue;
                }
            }
        }

        let mut message: Option<&[u8]> = None;

        // check if there is a message
        let rest = sd_and_msg.get(message_idx..);
        let mut is_utf8 = false;
        if let Some(mut msg) = rest {
            if msg.len() >= 3 && &msg[0..3] == b"\xEF\xBB\xBF" {
                msg = &msg[3..];
                is_utf8 = true;
            }

            if msg.len() != 0 {
                message = Some(msg);
            }
        }

        fn to_str(b: Option<&[u8]>) -> Result<Option<&str>, Error> {
            if let Some(bytes) = b {
                Ok(Some(std::str::from_utf8(bytes)?))
            } else {
                Ok(None)
            }
        }

        let message = if let Some(msg_bytes) = message {
            if is_utf8 {
                Some(Cow::Borrowed(std::str::from_utf8(msg_bytes)?.trim_end()))
            } else {
                Some(Cow::Owned(String::from_utf8_lossy(msg_bytes).trim_end().to_string()))
            }
        } else {
            None
        };

        Ok(Message {
            priority,
            timestamp: to_str(timestamp)?,
            hostname: to_str(hostname)?,
            app_name: to_str(app_name)?,
            proc_id: to_str(proc_id)?,
            message_id: to_str(message_id)?,
            structured_data,
            message,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::borrow::Cow::{Borrowed, Owned};

    #[test]
    fn parse_rfc5424_syslog_message() {
        // from docker alpine
        let input = b"<30>1 2020-02-13T00:51:39.527825Z docker-desktop 8b1089798cf8 1481 8b1089798cf8 - hello world\n";

        let expected = Message {
            priority: Priority {
                facility: 3,
                severity: 6,
            },
            timestamp: Some("2020-02-13T00:51:39.527825Z"),
            hostname: Some("docker-desktop"),
            app_name: Some("8b1089798cf8"),
            proc_id: Some("1481"),
            message_id: Some("8b1089798cf8"),
            structured_data: None,
            message: Some(Borrowed("hello world")),
        };

        let actual = Message::from_rfc5424_bytes(input).expect("could not parse input for syslog");

        assert_eq!(expected, actual);
    }

    #[test]
    fn parse_rfc5424_syslog_should_throw_error() {
        let input = b"<30>1 2020-02-13T00:51:39\n";

        let actual = Message::from_rfc5424_bytes(input);

        assert_eq!("missing syslog hostname", actual.unwrap_err().to_string());
    }

    #[test]
    fn parse_rfc5424_syslog_specs_example_1() {
        // example 1 from https://tools.ietf.org/html/rfc5424
        let input = b"<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - \xEF\xBB\xBF\xE2\x80\x99su root\xE2\x80\x99 failed for lonvick on /dev/pts/8\n";

        let expected = Message {
            priority: Priority {
                facility: 4,
                severity: 2,
            },
            timestamp: Some("2003-10-11T22:14:15.003Z"),
            hostname: Some("mymachine.example.com"),
            app_name: Some("su"),
            proc_id: None,
            message_id: Some("ID47"),
            structured_data: None,
            message: Some(Borrowed("’su root’ failed for lonvick on /dev/pts/8")),
        };

        let actual = Message::from_rfc5424_bytes(input).expect("could not parse input for syslog");

        assert_eq!(expected, actual);
    }

    #[test]
    fn parse_rfc5424_syslog_specs_example_2() {
        // example 2 from https://tools.ietf.org/html/rfc5424
        let input = b"<165>1 2003-08-24T05:14:15.000003-07:00 192.0.2.1 myproc 8710 - - %% It's time to make the do-nuts.\n";

        let expected = Message {
            priority: Priority {
                facility: 20,
                severity: 5,
            },
            timestamp: Some("2003-08-24T05:14:15.000003-07:00"),
            hostname: Some("192.0.2.1"),
            app_name: Some("myproc"),
            proc_id: Some("8710"),
            message_id: None,
            structured_data: None,
            message: Some(Borrowed("%% It's time to make the do-nuts.")),
        };

        let actual = Message::from_rfc5424_bytes(input).expect("could not parse message");

        assert_eq!(expected, actual);
    }

    #[test]
    fn parse_rfc5424_syslog_specs_example_3() {
        // example 3 from https://tools.ietf.org/html/rfc5424
        let input = b"<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut=\"3\" eventSource=\"Application\" eventID=\"1011\"] \xEF\xBB\xBFAn application event log entry...\n";

        let mut sd_params = HashMap::new();
        sd_params.insert("iut", "3");
        sd_params.insert("eventSource", "Application");
        sd_params.insert("eventID", "1011");

        let expected = Message {
            priority: Priority {
                facility: 20,
                severity: 5,
            },
            timestamp: Some("2003-10-11T22:14:15.003Z"),
            hostname: Some("mymachine.example.com"),
            app_name: Some("evntslog"),
            proc_id: None,
            message_id: Some("ID47"),
            structured_data: Some(vec![StructuredDataElement {
                id: "exampleSDID@32473",
                param: sd_params,
            }]),
            message: Some(Borrowed("An application event log entry...")),
        };

        let actual = Message::from_rfc5424_bytes(input).expect("could not parse input for syslog");

        assert_eq!(expected, actual);
    }

    #[test]
    fn parse_rfc5424_syslog_specs_example_4() {
        // example 4 from https://tools.ietf.org/html/rfc5424

        let input = b"<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut=\"3\" eventSource=\"Application\" eventID=\"1011\"][examplePriority@32473 class=\"high\"]";

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
            timestamp: Some("2003-10-11T22:14:15.003Z"),
            hostname: Some("mymachine.example.com"),
            app_name: Some("evntslog"),
            proc_id: None,
            message_id: Some("ID47"),
            structured_data: Some(sd),
            message: None,
        };

        let actual = Message::from_rfc5424_bytes(input).expect("could not parse input for syslog");

        assert_eq!(expected, actual);
    }

    #[test]
    fn parse_rfc5424_empty_valid_syslog() {
        let input = b"<0>1 - - - - - -";

        let expected = Message {
            priority: Priority {
                facility: 0,
                severity: 0,
            },
            timestamp: None,
            hostname: None,
            app_name: None,
            proc_id: None,
            message_id: None,
            structured_data: None,
            message: None,
        };

        let actual = Message::from_rfc5424_bytes(input).expect("could not parse input for syslog");

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
