CREATE INDEX attack_events_trap_recent
    ON attack_events (trap_id, occurred_at DESC, event_id DESC);
