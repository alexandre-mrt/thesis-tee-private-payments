use std::time::Duration;

pub struct Percentiles {
    pub count: usize,
    pub mean: Duration,
    pub p50: Duration,
    pub p95: Duration,
    pub p99: Duration,
    pub max: Duration,
}

pub fn percentiles(samples: &[Duration]) -> Option<Percentiles> {
    let last = samples.len().checked_sub(1)?;
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let at = |p: f64| {
        let rank = (p * sorted.len() as f64).ceil() as usize;
        sorted[rank.clamp(1, sorted.len()) - 1]
    };
    let total: Duration = sorted.iter().sum();
    Some(Percentiles {
        count: sorted.len(),
        mean: total.div_f64(sorted.len() as f64),
        p50: at(0.50),
        p95: at(0.95),
        p99: at(0.99),
        max: sorted[last],
    })
}

pub fn per_second(count: usize, elapsed: Duration) -> f64 {
    count as f64 / elapsed.as_secs_f64()
}

pub fn ms(duration: Duration) -> String {
    format!("{:.3} ms", duration.as_secs_f64() * 1e3)
}

pub fn line(label: &str, p: &Percentiles) -> String {
    format!(
        "{label}: n={} mean={} p50={} p95={} p99={} max={}",
        p.count,
        ms(p.mean),
        ms(p.p50),
        ms(p.p95),
        ms(p.p99),
        ms(p.max)
    )
}

pub fn rate_line(label: &str, count: usize, elapsed: Duration) -> String {
    format!(
        "{label}: {} in {:.3} s = {:.1} /s ({} each)",
        count,
        elapsed.as_secs_f64(),
        per_second(count, elapsed),
        ms(elapsed.div_f64(count.max(1) as f64))
    )
}
