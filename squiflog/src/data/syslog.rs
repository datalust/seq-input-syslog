use crate::{
    error::{
        err_msg,
        Error,
    },
    data::parsers
};
use std::borrow::Cow;
use chrono::{Utc, DateTime};

#[derive(Debug, Eq, PartialEq)]
pub struct Priority {
    pub facility: u8,
    pub severity: u8,
}

impl Priority {
    fn from_raw(raw: u8) -> Self {
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
    pub params: Vec<(&'a str, String)>,
}

#[derive(Debug, Eq, PartialEq)]
pub struct Message<'a> {
    pub priority: Priority,
    pub timestamp: Option<DateTime<Utc>>,
    pub hostname: Option<&'a str>,
    pub app_name: Option<&'a str>,
    pub proc_id: Option<&'a str>,
    pub message_id: Option<&'a str>,
    pub structured_data: Option<Vec<StructuredDataElement<'a>>>,
    pub message: Option<Cow<'a, str>>,
}

impl<'a> Message<'a> {
    pub fn from_str(s: &'a str) -> Self {
        Self::from_bytes(s.as_bytes())
    }

    pub fn from_bytes(s: &'a [u8]) -> Self {
        Self::from_rfc5424_bytes(s).unwrap_or_else(|_| Self::from_rfc3164_bytes(s, &Utc::now()))
    }

    // RFC3164 format: <PRIVAL>TIMESTAMP HOSTNAME TAG: (MSG)
    // We treat the tag as part of the message.
    pub fn from_rfc3164_bytes(msg: &'a [u8], now: &DateTime<Utc>) -> Self {
        let mut unparsed = msg;
        let mut result = Message {
            priority: Priority::from_raw(13),
            timestamp: None,
            hostname: None,
            app_name: None,
            proc_id: None,
            message_id: None,
            structured_data: None,
            message: None,
        };

        if let Ok((priority, rem)) = parsers::priority(unparsed) {
            result.priority = Priority::from_raw(priority);
            unparsed = rem;

            if let Ok((timestamp, rem)) = parsers::loose_timestamp(unparsed, now) {
                result.timestamp = Some(timestamp);
                unparsed = rem;

                if let Ok((_, rem)) = parsers::byte(unparsed, b' ') {
                    unparsed = rem;

                    if let Ok((hostname, rem)) = parsers::header_item(unparsed, "hostname") {
                        result.hostname = hostname;
                        unparsed = rem;
                    }
                }
            }
        }

        result.message = if unparsed.len() > 0 { Some(String::from_utf8_lossy(unparsed)) } else { None };

        if result.timestamp.is_none() {
            result.timestamp = Some(now.clone())
        }

        result
    }

    // RFC5424 format: <PRIVAL>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA (MSG)
    pub fn from_rfc5424_bytes(msg: &'a [u8]) -> Result<Self, Error> {
        let (priority, rem) = parsers::priority(msg)?;

        let mut result = Message {
            priority: Priority::from_raw(priority),
            timestamp: None,
            hostname: None,
            app_name: None,
            proc_id: None,
            message_id: None,
            structured_data: None,
            message: None,
        };

        let (version_item, rem) = parsers::header_item(rem, "version")?;
        match version_item {
            Some("1") => (),
            _ => return Err(err_msg("invalid message, version not 1"))
        };

        let ts_rem;
        let ts_attempt = parsers::iso8601_timestamp(rem);
        if let Ok((timestamp, rem)) = ts_attempt {
            result.timestamp = Some(timestamp);
            ts_rem = rem;
        } else {
            let err = ts_attempt.unwrap_err();
            let (_, nil_rem) = parsers::byte(rem, b'-').map_err(move |_| err)?;
            ts_rem = nil_rem;
        }

        let (_, rem) = parsers::byte(ts_rem, b' ')?;

        let (hostname, rem) = parsers::header_item(rem, "hostname")?;
        result.hostname = hostname;

        let (app_name, rem) = parsers::header_item(rem, "app_name")?;
        result.app_name = app_name;

        let (proc_id, rem) = parsers::header_item(rem, "proc_id")?;
        result.proc_id = proc_id;

        let (message_id, mut rem) = parsers::header_item(rem, "message_id")?;
        result.message_id = message_id;

        let mut maybe_sd = parsers::structured_data_element(rem);
        if maybe_sd.is_ok() {
            while let Ok((sde, sd_rem)) = maybe_sd {
                match result.structured_data {
                    None => result.structured_data = Some(vec![sde]),
                    Some(ref mut sd) => sd.push(sde)
                }
                rem = sd_rem;
                maybe_sd = parsers::structured_data_element(rem);
            }
        } else {
            let (_, sd_rem) = parsers::byte(rem, b'-')?;
            rem = sd_rem;
        }

        if let Ok((_, rem)) = parsers::byte(rem, b' ') {
            let mut is_utf8 = false;
            let mut message_bytes = rem;
            if message_bytes.len() >= 3 && &message_bytes[..3] == b"\xEF\xBB\xBF" {
                message_bytes = &message_bytes[3..];
                is_utf8 = true;
            }

            result.message = if is_utf8 {
                let trimmed = std::str::from_utf8(message_bytes)?.trim();
                if trimmed.len() > 0 {
                    Some(Cow::Borrowed(trimmed))
                } else {
                    None
                }
            } else {
                let owned = String::from_utf8_lossy(message_bytes);
                let trimmed = owned.trim();
                if trimmed.len() > 0 {
                    Some(Cow::Owned(trimmed.to_owned()))
                } else {
                    None
                }
            };
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Datelike, TimeZone};
    use crate::test_util::to_timestamp;
    use std::borrow::Cow::Borrowed;

    impl<'a> StructuredDataElement<'a> {
        fn from_str(s: &'a str) -> Result<Self, Error> {
            let (r, rem) = parsers::structured_data_element(s.as_bytes())?;
            if rem.len() > 0 {
                Err(err_msg("too much input"))
            } else {
                Ok(r)
            }
        }
    }

    #[test]
    fn parse_rfc5424_syslog_message() {
        // from docker alpine
        let input = b"<30>1 2020-02-13T00:51:39.527825Z docker-desktop 8b1089798cf8 1481 8b1089798cf8 - hello world\n";

        let expected = Message {
            priority: Priority {
                facility: 3,
                severity: 6,
            },
            timestamp: to_timestamp("2020-02-13T00:51:39.527825Z"),
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
    fn parse_rfc5424_syslog_requires_hostname() {
        let input = b"<30>1 2020-02-13T00:51:39Z ";

        let actual = Message::from_rfc5424_bytes(input);

        assert_eq!("missing hostname", actual.unwrap_err().to_string());
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
            timestamp: to_timestamp("2003-10-11T22:14:15.003Z"),
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
            timestamp: to_timestamp("2003-08-24T05:14:15.000003-07:00"),
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

        let mut sd_params = vec![];
        sd_params.push(("iut", "3".to_owned()));
        sd_params.push(("eventSource", "Application".to_owned()));
        sd_params.push(("eventID", "1011".to_owned()));

        let expected = Message {
            priority: Priority {
                facility: 20,
                severity: 5,
            },
            timestamp: to_timestamp("2003-10-11T22:14:15.003Z"),
            hostname: Some("mymachine.example.com"),
            app_name: Some("evntslog"),
            proc_id: None,
            message_id: Some("ID47"),
            structured_data: Some(vec![StructuredDataElement {
                id: "exampleSDID@32473",
                params: sd_params,
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

        let mut sd_params = vec![];
        sd_params.push(("iut", "3".to_owned()));
        sd_params.push(("eventSource", "Application".to_owned()));
        sd_params.push(("eventID", "1011".to_owned()));

        let mut sd_params2 = vec![];
        sd_params2.push(("class", "high".to_owned()));

        let sd = vec![
            StructuredDataElement {
                id: "exampleSDID@32473",
                params: sd_params,
            },
            StructuredDataElement {
                id: "examplePriority@32473",
                params: sd_params2,
            },
        ];

        let expected = Message {
            priority: Priority {
                facility: 20,
                severity: 5,
            },
            timestamp: to_timestamp("2003-10-11T22:14:15.003Z"),
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
        let input = "[exampleSDID@32473 iut=\"3\" eventSource=\"Application\" eventID=\"1011\"]";

        let mut sd_params = vec![];
        sd_params.push(("iut", "3".to_owned()));
        sd_params.push(("eventSource", "Application".to_owned()));
        sd_params.push(("eventID", "1011".to_owned()));

        let expected = StructuredDataElement {
            id: "exampleSDID@32473",
            params: sd_params,
        };

        let actual = StructuredDataElement::from_str(input)
            .expect("could not parse input for structured data element");

        assert_eq!(expected, actual);
    }

    #[test]
    fn parse_rfc3164_example_2() {
        let input = b"<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8";

        let now = Utc.ymd(2020, 10, 11).and_hms(0, 0, 0);
        let msg = Message::from_rfc3164_bytes(input, &now);

        assert_eq!(msg.priority.facility, 4);
        assert_eq!(msg.priority.severity, 2);
        assert_eq!(msg.timestamp.unwrap().month(), 10); // Rest depends on local timezone ":-)
        assert_eq!(msg.hostname, Some("mymachine"));

        // The 'tag' remains in the message; although we could extract 'su' as the tag, adherence to
        // this format seems very patchy, and we're more likely to end up breaking messages that
        // happen to include `:` by mistake.
        assert_eq!(msg.message, Some(Borrowed("su: 'su root' failed for lonvick on /dev/pts/8")));
    }

    #[test]
    fn parse_rfc3164_example_1() {
        let input = b"Use the BFG!";

        let msg = Message::from_rfc3164_bytes(input, &Utc::now());

        assert_eq!("Use the BFG!", msg.message.unwrap());
    }
}
