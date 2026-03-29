use hifitime::Epoch;
use triblespace::prelude::valueschemas::NsTAIInterval;
use triblespace::prelude::{TryToValue, Value};

pub(crate) fn now_epoch() -> Epoch {
    Epoch::now().unwrap_or_else(|_| Epoch::from_gregorian_utc(1970, 1, 1, 0, 0, 0, 0))
}

pub(crate) fn epoch_interval(epoch: Epoch) -> Value<NsTAIInterval> {
    (epoch, epoch).try_to_value().unwrap()
}

pub(crate) fn interval_key(interval: Value<NsTAIInterval>) -> i128 {
    let (lower_ns, _): (i128, i128) = interval.try_from_value().unwrap();
    lower_ns
}

/// Width of a time range in nanoseconds (end - start). Zero for point intervals.
pub(crate) fn interval_width(start: Value<NsTAIInterval>, end: Value<NsTAIInterval>) -> i128 {
    let (_, upper_ns): (i128, i128) = end.try_from_value().unwrap();
    let (lower_ns, _): (i128, i128) = start.try_from_value().unwrap();
    upper_ns.saturating_sub(lower_ns).max(0)
}

/// Format the lower bound of an interval as a TAI timestamp.
pub(crate) fn format_tai_interval_timestamp(interval: Value<NsTAIInterval>) -> String {
    let (lower, _): (Epoch, Epoch) = interval.try_from_value().unwrap();
    format_tai_timestamp(lower)
}

pub(crate) fn format_tai_timestamp(epoch: Epoch) -> String {
    let (y, m, d, hh, mm, ss, _) = epoch.to_gregorian_tai();
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02} TAI")
}

pub(crate) fn format_time_range(interval_start: Value<NsTAIInterval>, interval_end: Value<NsTAIInterval>) -> String {
    let (start, _): (Epoch, Epoch) = interval_start.try_from_value().unwrap();
    let (_, end): (Epoch, Epoch) = interval_end.try_from_value().unwrap();
    let (y1, m1, d1, h1, mi1, s1, _) = start.to_gregorian_tai();
    let (y2, m2, d2, h2, mi2, s2, _) = end.to_gregorian_tai();
    format!(
        "{y1:04}-{m1:02}-{d1:02}T{h1:02}:{mi1:02}:{s1:02}..{y2:04}-{m2:02}-{d2:02}T{h2:02}:{mi2:02}:{s2:02}"
    )
}
