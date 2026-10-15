-- Opened decoy files are normalized graph actions with a stable bait ID.
CREATE INDEX normalized_actions_bait_engagement
    ON normalized_attack_actions(trap_id, (environment->>'bait_id'))
    WHERE action_kind = 'deception.bait_open';
