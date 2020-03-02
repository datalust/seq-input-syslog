use crate::error::{Error, err_msg};
use chrono::{Utc, DateTime, Local, Datelike, Duration, Timelike, TimeZone};

pub fn priority(i: &[u8]) -> Result<(u8, &[u8]), Error> {
    let (content, rem) = delimited(i, b'<', b'>')?;
    if content.len() == 0 || content.iter().any(|b| !char::is_digit(*b as char, 10)) {
        return Err(err_msg("invalid priority content"));
    }
    let pval = std::str::from_utf8(content)?.parse::<u8>()?;
    Ok((pval, rem))
}

pub fn any_byte(i: &[u8]) -> Result<(u8, &[u8]), Error> {
    if i.len() == 0 {
        Err(err_msg("unexpected end of input"))
    } else {
        Ok((i[0], &i[1..]))
    }
}

pub fn byte(i: &[u8], b: u8) -> Result<&[u8], Error> {
    if let Ok((actual, rem)) = any_byte(i) {
        Ok(rem)
    } else {
        Err(err_msg("unexpected byte"))
    }
}

pub fn until(i: &[u8], end: u8) -> Result<(&[u8], &[u8]), Error> {
    let mut rem = i;
    let mut count = 0;
    while rem.len() != 0 {
        if rem[0] == end {
            return Ok((&i[0..count], rem));
        }
        rem = &rem[1..];
        count += 1;
    }

    Err(err_msg("missing end delimiter"))
}

pub fn delimited(i: &[u8], start: u8, end: u8) -> Result<(&[u8], &[u8]), Error> {
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

pub fn take(i: &[u8], count: usize) -> Result<(&[u8], &[u8]), Error> {
    if i.len() < count {
        return Err(err_msg("the input is too short"));
    }

    Ok((&i[..count], &i[count..]))
}

pub fn iso8601_timestamp(i: &[u8]) -> Result<(DateTime<Utc>, &[u8]), Error> {
    let (to_space, rem) = until(i, b' ')?; // Cheating a little here; we shouldn't need any trailing delimiter
    let maybe_ts = std::str::from_utf8(to_space)?;
    let utc = DateTime::parse_from_rfc3339(maybe_ts)?.with_timezone(&Utc);
    Ok((utc, rem))
}

pub fn loose_timestamp<'a, 'b>(i: &'a [u8], now: &'b DateTime<Utc>) -> Result<(DateTime<Utc>, &'a [u8]), Error> {
    if let Ok((isots, rem)) = iso8601_timestamp(i) {
        return Ok((isots, rem));
    }

    let (mdhms, rem) = take(i, 15)?;

    let cheat_and_allocate_a_year = std::str::from_utf8(mdhms)?.to_string() + " 1980";
    let local = Local.datetime_from_str(&cheat_and_allocate_a_year, "%h %d %H:%M:%S %Y")?;

    let year_offset = if &mdhms[0..3] == &b"Dec"[..] && now.month() == 1 {
        - 1
    } else if &mdhms[0..3] == &b"Jan"[..] && now.month() == 12 {
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
pub fn header_item(i: &[u8]) -> Result<(Option<&str>, &[u8]), Error> {
    let (content, rem) = until(i, b' ')?;
    let rem = byte(rem, b' ')?;
    if &content[..] == &b"-"[..] {
        Ok((None, rem))
    } else {
        Ok((Some(std::str::from_utf8(content)?), rem))
    }
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
        let (onetwo, rem) = until(i, b'3').expect("could not parse items");
        assert_eq!(&b"12"[..], onetwo);
    }
}