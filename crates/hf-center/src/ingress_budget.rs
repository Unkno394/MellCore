//! Bounded work before decoding/authentication, followed by per-agent quotas.
//! Dropped packets receive no ACK, so the durable outbox retries.
use std::{collections::HashMap, time::{Duration, Instant}};
use uuid::Uuid;

#[derive(Default)]
pub(crate) struct IngressBudget {
    windows: HashMap<Uuid, (Instant, usize, usize)>,
    preauth: Option<(Instant, usize, usize)>,
}

impl IngressBudget {
    /// This is deliberately global: all Hysteria UDP forwards can appear to
    /// originate from loopback, so a peer-IP map would not isolate attackers.
    /// Keep the memory and decode budget bounded even for forged agent IDs.
    pub(crate) fn allow_preauth(&mut self, bytes: usize, now: Instant) -> bool {
        let window = self.preauth.get_or_insert((now, 0, 0));
        if now.duration_since(window.0) >= Duration::from_secs(1) { *window = (now, 0, 0); }
        if window.1 >= 4096 || bytes > (16 * 1024 * 1024_usize).saturating_sub(window.2) {
            return false;
        }
        window.1 += 1;
        window.2 += bytes;
        true
    }

    pub(crate) fn allow(&mut self, agent: Uuid, bytes: usize, now: Instant) -> bool {
        if !self.windows.contains_key(&agent) && self.windows.len() >= 4096 {
            self.windows.retain(|_, window| now.duration_since(window.0) < Duration::from_secs(1));
            if self.windows.len() >= 4096 { return false; }
        }
        let window = self.windows.entry(agent).or_insert((now, 0, 0));
        if now.duration_since(window.0) >= Duration::from_secs(1) { *window = (now, 0, 0); }
        if window.1 >= 128 || bytes > (2 * 1024 * 1024_usize).saturating_sub(window.2) { return false; }
        window.1 += 1;
        window.2 += bytes;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn noisy_agent_does_not_consume_another_agents_budget() {
        let now = Instant::now(); let a = Uuid::new_v4(); let b = Uuid::new_v4();
        let mut budget = IngressBudget::default();
        for _ in 0..128 { assert!(budget.allow(a, 10, now)); }
        assert!(!budget.allow(a, 10, now));
        assert!(budget.allow(b, 10, now));
        assert!(!budget.allow(b, 3 * 1024 * 1024, now));
        assert!(budget.allow(a, 10, now + Duration::from_secs(1)));
    }

    #[test]
    fn forged_ids_cannot_force_unbounded_decoding_or_state() {
        let now = Instant::now();
        let mut budget = IngressBudget::default();
        for _ in 0..4096 { assert!(budget.allow_preauth(1, now)); }
        assert!(!budget.allow_preauth(1, now));
        assert!(budget.windows.is_empty());
        assert!(budget.allow_preauth(1, now + Duration::from_secs(1)));
    }
}
