use std::time::Duration;

#[tokio::test]
async fn tokio_interval_stays_within_bounds() {
    let interval = Duration::from_millis(50);
    let mut ticker = tokio::time::interval(interval);
    // Skip the immediate first tick to measure steady-state intervals.
    ticker.tick().await;
    let mut previous = tokio::time::Instant::now();
    for _ in 0..5 {
        ticker.tick().await;
        let now = tokio::time::Instant::now();
        let elapsed = now.duration_since(previous);
        assert!(
            elapsed + Duration::from_millis(2) >= interval,
            "tick fired too early: {:?} < {:?}",
            elapsed,
            interval
        );
        assert!(
            elapsed <= interval + Duration::from_millis(20),
            "tick drift too large: {:?} > {:?}",
            elapsed,
            interval + Duration::from_millis(20)
        );
        previous = now;
    }
}
