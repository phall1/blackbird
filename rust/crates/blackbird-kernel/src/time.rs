//! Daemon clock. Callers never compare a stored instant against their own clock:
//! remaining time is computed here, and wire instants are UTC.

use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) fn now_us() -> i64 {
    let Ok(elapsed) = SystemTime::now().duration_since(UNIX_EPOCH) else {
        return 0;
    };
    i64::try_from(elapsed.as_micros()).unwrap_or(i64::MAX)
}

pub(crate) fn rfc3339(us: i64) -> String {
    let secs = us.div_euclid(1_000_000);
    let micros = us.rem_euclid(1_000_000) as u32;
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400) as u32;
    let (year, month, day) = civil_from_days(days);
    let hour = tod / 3600;
    let minute = (tod % 3600) / 60;
    let second = tod % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{micros:06}Z")
}

pub(crate) fn ms_between(later_us: i64, earlier_us: i64) -> i64 {
    (later_us - earlier_us).div_euclid(1000)
}

/// Howard Hinnant's public-domain `civil_from_days`. `days` counts from the Unix epoch.
fn civil_from_days(days: i64) -> (i32, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let year = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { year + 1 } else { year };
    (year as i32, month as u32, day as u32)
}

#[cfg(test)]
mod tests {
    use super::rfc3339;

    #[test]
    fn formats_the_unix_epoch_and_the_next_day() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00.000000Z");
        assert_eq!(rfc3339(1), "1970-01-01T00:00:00.000001Z");
        assert_eq!(rfc3339(86_400 * 1_000_000), "1970-01-02T00:00:00.000000Z");
    }
}
