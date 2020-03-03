use crate::error::{Error, err_msg};
use chrono::{Utc, DateTime, Local, Datelike, Timelike, TimeZone};
use crate::data::syslog::StructuredDataElement;

type ParserResult<'a, T> = Result<(T, &'a [u8]), Error>;

pub fn priority(i: &[u8]) -> ParserResult<u8> {
    let (content, rem) = delimited(i, b'<', b'>')?;
    if content.len() == 0 || content.iter().any(|b| !char::is_digit(*b as char, 10)) {
        return Err(err_msg("invalid priority content"));
    }
    let pval = std::str::from_utf8(content)?.parse::<u8>()?;
    Ok((pval, rem))
}

pub fn any_byte(i: &[u8]) -> ParserResult<u8> {
    if i.len() == 0 {
        Err(err_msg("unexpected end of input"))
    } else {
        Ok((i[0], &i[1..]))
    }
}

pub fn byte(i: &[u8], b: u8) -> ParserResult<()> {
    if let Ok((actual, rem)) = any_byte(i) {
        if actual == b {
            Ok(((), rem))
        } else {
            Err(err_msg("unexpected byte"))
        }
    } else {
        Err(err_msg("expected byte, unexpected end of input"))
    }
}

pub fn until(i: &[u8], end: u8) -> ParserResult<&[u8]> {
    let mut rem = i;
    let mut count = 0;
    while rem.len() != 0 {
        if rem[0] == end {
            return Ok((&i[0..count], rem));
        }
        rem = &rem[1..];
        count += 1;
    }

    Err(err_msg(format!("missing end `{}` delimiter", end as char)))
}

pub fn delimited(i: &[u8], start: u8, end: u8) -> ParserResult<&[u8]> {
    let rem = i;
    if rem.len() == 0 || rem[0] != start {
        return Err(err_msg("missing start delimiter"));
    }

    let rem = &rem[1..];
    if rem.len() == 0 {
        return Err(err_msg("missing delimited content"));
    }

    let (content, rem) = until(rem, end)?;

    Ok((content, &rem[1..]))
}

pub fn take(i: &[u8], count: usize) -> ParserResult<&[u8]> {
    if i.len() < count {
        return Err(err_msg("the input is too short"));
    }

    Ok((&i[..count], &i[count..]))
}

pub fn iso8601_timestamp(i: &[u8]) -> ParserResult<DateTime<Utc>> {
    let (to_space, rem) = until(i, b' ')?; // Cheating a little here; we shouldn't need any trailing delimiter
    let maybe_ts = std::str::from_utf8(to_space)?;
    let utc = DateTime::parse_from_rfc3339(maybe_ts)?.with_timezone(&Utc);
    Ok((utc, rem))
}

pub fn loose_timestamp<'a, 'b>(i: &'a [u8], now: &'b DateTime<Utc>) -> ParserResult<'a, DateTime<Utc>> {
    if let Ok((iso_ts, rem)) = iso8601_timestamp(i) {
        return Ok((iso_ts, rem));
    }

    let (month_day_h_m_s, rem) = take(i, 15)?;

    let cheat_and_allocate_a_year = std::str::from_utf8(month_day_h_m_s)?.to_string() + " 1980";
    let local = Local.datetime_from_str(&cheat_and_allocate_a_year, "%h %d %H:%M:%S %Y")?;

    let year_offset = if &month_day_h_m_s[0..3] == &b"Dec"[..] && now.month() == 1 {
        - 1
    } else if &month_day_h_m_s[0..3] == &b"Jan"[..] && now.month() == 12 {
        1
    } else {
        0
    };

    let with_year = Local.ymd(now.year() + year_offset, local.month(), local.day())
        .and_hms(local.hour(), local.minute(), local.second());

    let utc = with_year.with_timezone(&Utc);
    Ok((utc, rem))
}

// Consumes (requires) a trailing space
pub fn header_item<'a>(i: &'a [u8], name: &'static str) -> ParserResult<'a, Option<&'a str>> {
    let (content, rem) = until(i, b' ').map_err(|_| err_msg(format!("missing {}", name)))?;
    let (_, rem) = byte(rem, b' ')?;
    if &content[..] == &b"-"[..] {
        Ok((None, rem))
    } else {
        Ok((Some(std::str::from_utf8(content)?), rem))
    }
}

pub fn param_value_content_char(i: &[u8]) -> ParserResult<u8> {
    let (b, rem) = any_byte(i)?;
    if b == b'"' {
        Err(err_msg("no param value content char found"))
    } else if b == b'\\' {
        let (next, following_rem) = any_byte(rem)?;
        if next == b'\\' || next == b'\"' || next == b']' {
            Ok((next, following_rem))
        } else {
            Ok((b, rem))
        }
    } else {
        Ok((b, rem))
    }
}

pub fn structured_data_element(i: &[u8]) -> ParserResult<StructuredDataElement> {
    let (_, rem) = byte(i, b'[')?;
    let (id, mut rem) = sd_name(rem)?;

    let mut params = vec![];
    while let Ok((_, sp_rem)) = byte(rem, b' ') {
        let (param, param_rem) = param(sp_rem)?;
        params.push(param);
        rem = param_rem;
    }

    let (_, rem) = byte(rem, b']')?;
    Ok((StructuredDataElement{id, params}, rem))
}

pub fn param_value_content(i: &[u8]) -> ParserResult<String> {
    let mut bytes = vec![];
    let mut rem = i;
    let mut maybe_content = param_value_content_char(rem);
    while let Ok((b, rest)) = maybe_content {
        bytes.push(b);
        rem = rest;
        maybe_content = param_value_content_char(rem);
    }
    Ok((std::str::from_utf8(&bytes[..])?.into(), rem))
}

pub fn param_value(i: &[u8]) -> ParserResult<String> {
    let (_, rem) = byte(i, b'"')?;
    let (content, rem) = param_value_content(rem)?;
    let (_, rem) = byte(rem, b'"')?;
    Ok((content, rem))
}

pub fn sd_name(i: &[u8]) -> ParserResult<&str> {
    let disallowed: &[u8] = &b"\" ]="[..];
    let mut rem = i;
    let mut count = 0;
    let mut maybe_char = any_byte(rem);
    while let Ok((b, rest)) = maybe_char {
        if disallowed.contains(&b) {
            break;
        }
        rem = rest;
        count += 1;
        maybe_char = any_byte(rem);
    }
    if count == 0 {
        Err(err_msg("missing param name"))
    } else {
        Ok((std::str::from_utf8(&i[..count])?, rem))
    }
}

pub fn param(i: &[u8]) -> ParserResult<(&str, String)> {
    let (name, rem) = sd_name(i)?;
    let (_, rem) = byte(rem, b'=')?;
    let (value, rem) = param_value(rem)?;
    Ok(((name, value), rem))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delimited_accepts_valid_content() {
        let c = b"(hello, world) and then";
        let (content, rem) = delimited(c, b'(', b')').expect("failed to parse delimiters");
        assert_eq!(b"hello, world", content);
        assert_eq!(b" and then", rem);
    }

    #[test]
    fn delimited_rejects_invalid_content() {
        let cases = [&b"(test"[..], &b"test)"[..], &b" "[..], &b""[..], &b"("[..], &b")"[..]].to_vec();
        for case in cases {
            let expect_err = delimited(case, b'(', b')');
            assert!(expect_err.is_err(), case);
        }
    }

    #[test]
    fn parses_loose_timestamps() {
        let ts = b"Oct 28 12:34:56";
        loose_timestamp(ts, &Utc::now()).expect("could not parse timestamp");
    }

    #[test]
    fn parses_iso8601_timestamps() {
        let ts = b"1985-04-12T23:20:50.52Z "; // Note end delimiter
        iso8601_timestamp(ts).expect("could not parse timestamp");
    }

    #[test]
    fn parses_tight_timestamps() {
        let ts = b"1985-04-12T23:20:50.52Z "; // Note end delimiter
        loose_timestamp(ts, &Utc::now()).expect("could not parse timestamp");
    }

    #[test]
    fn until_excludes_end() {
        let i = b"12345";
        let (one_two, _) = until(i, b'3').expect("could not parse items");
        assert_eq!(&b"12"[..], one_two);
    }

    #[test]
    fn double_quotes_escaped_in_param_values() {
        let i = b"\\\"test";
        let (b, _) = param_value_content_char(i).expect("parser failed");
        assert_eq!(b'"' as char, b as char);
    }

    #[test]
    fn normal_chars_as_is_in_param_values() {
        let i = b"test";
        let (b, _) = param_value_content_char(i).expect("parser failed");
        assert_eq!(b't', b);
    }

    #[test]
    fn param_value_content_excludes_closing_quotes() {
        let i = b"text\\\"stuff\" and more";
        let (s, _) = param_value_content(i).expect("parser failed");
        assert_eq!("text\"stuff", s);
    }

    #[test]
    fn invalid_escape_sequence_is_literal() {
        let i = b"\"text\\xstuff\"";
        let (s, _) = param_value(i).expect("parser failed");
        assert_eq!("text\\xstuff", s);
    }

    #[test]
    fn param_value_is_content() {
        let i = b"\"this is a value\"";
        let (s, _) = param_value(i).expect("parser failed");
        assert_eq!("this is a value", s);
    }

    #[test]
    fn param_name_must_not_be_empty() {
        let i = b"=nothing";
        sd_name(i).expect_err("should fail");
    }

    #[test]
    fn param_name_is_parsed() {
        let i = b"test=nothing";
        let (n, _) = sd_name(i).expect("parser failed");
        assert_eq!("test", n);
    }

    #[test]
    fn param_name_excludes_bracket() {
        let i = b"test]nothing";
        let (n, _) = sd_name(i).expect("parser failed");
        assert_eq!("test", n);
    }

    #[test]
    fn param_is_name_value_pair() {
        let i = b"eventSource=\"Application\"";
        let ((name, value), _) = param(i).expect("parser failed");
        assert_eq!("eventSource", name);
        assert_eq!("Application", value);
    }

    #[test]
    fn param_requires_eq_separator() {
        let i = b"eventSource]\"Application\"";
        param(i).expect_err("should fail");
    }

    #[test]
    fn structured_data_elements_are_parsed() {
        let i = b"[test name=\"value\" another=\"another value\"]";
        let (sd, _) = structured_data_element(i).expect("parser failed");
        assert_eq!("test", sd.id);
        assert_eq!(2, sd.params.len());
    }
}
