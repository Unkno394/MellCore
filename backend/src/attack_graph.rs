//! Incremental, explainable attack-sequence matching backed by PostgreSQL.
//! The matcher compares normalized action/resource/outcome facts; it never
//! promotes similarity to a confirmed escape without a confirmed host event.

use serde_json::{Value, json};
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

use crate::telemetry::IncomingEvent;

#[derive(Debug)]
struct Action {
    kind: String,
    process: String,
    resource: String,
    outcome: String,
    session_key: String,
    environment: Value,
}

#[derive(Debug)]
struct Node {
    id: Uuid,
    technique_id: Uuid,
    evidence_level: String,
    is_start: bool,
    node_count: i64,
}

fn text_field(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| value.get(*key).and_then(Value::as_str).map(str::to_owned))
}

fn normalize(event: &IncomingEvent) -> Action {
    let command = text_field(&event.payload, &["command", "input", "exe"]).unwrap_or_default();
    let lower = command.to_ascii_lowercase();
    let path = text_field(&event.payload, &["path", "resource", "file"]).unwrap_or_default();
    let lower_path = path.to_ascii_lowercase();
    let resource = if lower.contains("docker.sock") || lower.contains("docker ") || lower.contains("podman") {
        "container_runtime"
    } else if lower.contains("unshare") || lower.contains("nsenter") || lower.contains("mount") || lower.contains("chroot") {
        "namespace_tool"
    } else if lower_path.contains("/proc") || lower_path.contains("/sys") || lower_path.contains("/host")
        || lower.contains("/proc") || lower.contains("/sys") || lower.contains("/host")
        || lower_path.contains("/var/run") || lower_path.contains("/run/")
    {
        "host_sensitive"
    } else {
        "other"
    };
    let command_first = lower.split_whitespace().next().unwrap_or("").rsplit('/').next().unwrap_or("");
    let command_process = if ["docker", "podman", "ctr", "crictl"].contains(&command_first) {
        "container_runtime_client"
    } else if ["mount", "unshare", "nsenter", "chroot", "pivot_root"].contains(&command_first) {
        "namespace_utility"
    } else if ["sudo", "su", "setcap", "capsh"].contains(&command_first) {
        "privilege_utility"
    } else if ["sh", "bash", "dash", "zsh"].contains(&command_first) {
        "shell"
    } else {
        "other_executable"
    };
    let (kind, process, resource) = match event.event_type.as_str() {
        "command.executed" => ("process.command", command_process, resource),
        "filesystem.accessed" => ("filesystem.access", "filesystem_operation", resource),
        "security.host_exec_from_trap" => ("boundary.host_exec", "host_process", "host_context"),
        "security.namespace_mismatch" => ("boundary.namespace_mismatch", "process", "namespace_escape"),
        "security.escape_confirmed" => ("boundary.escape_confirmed", "host_process", "confirmed_escape"),
        "connection.opened" | "connection.closed" => ("network.connection", "network_service", "network"),
        "auth.attempted" | "auth.failed" | "auth.succeeded" => ("identity.authentication", "ssh_service", "authentication"),
        "session.started" | "session.ended" => ("session.lifecycle", "ssh_service", "session"),
        _ => ("event.other", "unknown", "other"),
    };
    let outcome = if event.event_type == "security.escape_confirmed"
        && event.metadata.get("assessment").and_then(Value::as_str) == Some("confirmed")
    {
        "confirmed"
    } else if event.payload.get("accepted").and_then(Value::as_bool) == Some(false)
        || event.event_type == "auth.failed"
    {
        "denied"
    } else if event.payload.get("exit_status").and_then(Value::as_i64).is_some_and(|code| code != 0) {
        "failed"
    } else {
        "observed"
    };
    let session_key = event.session_id.clone().unwrap_or_else(|| {
        let pid = event.payload.get("pid").and_then(Value::as_u64);
        match pid {
            Some(pid) => format!("pid:{pid}"),
            None => format!("event:{}", event.event_id),
        }
    });
    Action {
        kind: kind.into(), process: process.into(), resource: resource.into(), outcome: outcome.into(), session_key,
        environment: json!({
            "service_type": event.service_type,
            "protocol": event.protocol,
            "destination_port": event.destination_port,
            "source": event.metadata.get("source"),
            "cgroup": event.payload.get("cgroup"),
            "pid_namespace": event.payload.get("pid_namespace"),
            "mount_namespace": event.payload.get("mount_namespace"),
        }),
    }
}

pub async fn observe(
    tx: &mut Transaction<'_, Postgres>, agent_id: Uuid, server_id: Uuid, event: &IncomingEvent,
) -> Result<(), sqlx::Error> {
    let action = normalize(event);
    sqlx::query("INSERT INTO normalized_attack_actions(event_id,agent_id,server_id,trap_id,session_key,action_kind,process_class,resource_class,outcome,environment) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT(event_id) DO NOTHING")
        .bind(event.event_id).bind(agent_id).bind(server_id).bind(event.trap_id)
        .bind(&action.session_key).bind(&action.kind).bind(&action.process).bind(&action.resource)
        .bind(&action.outcome).bind(&action.environment).execute(&mut **tx).await?;

    let rows = sqlx::query(
        "SELECT n.node_id,n.technique_id,n.resource_class,n.expected_outcome,n.evidence_level,\
         NOT EXISTS(SELECT 1 FROM attack_graph_edges e WHERE e.to_node=n.node_id) AS is_start,\
         (SELECT count(*) FROM attack_graph_nodes alln WHERE alln.technique_id=n.technique_id) AS node_count\
         FROM attack_graph_nodes n JOIN attack_techniques t USING(technique_id)\
         WHERE t.status='known' AND n.action_kind=$1 AND (n.resource_class='*' OR n.resource_class=$2)\
         AND (n.expected_outcome='*' OR n.expected_outcome=$3)"
    ).bind(&action.kind).bind(&action.resource).bind(&action.outcome).fetch_all(&mut **tx).await?;
    let nodes = rows.into_iter().map(|row| Node {
        id: row.get("node_id"), technique_id: row.get("technique_id"), evidence_level: row.get("evidence_level"),
        is_start: row.get("is_start"), node_count: row.get("node_count"),
    }).collect::<Vec<_>>();

    let mut touched_techniques = Vec::new();
    for node in nodes {
        if !touched_techniques.contains(&node.technique_id) { touched_techniques.push(node.technique_id); }
        let prior = sqlx::query("SELECT active_nodes,evidence_event_ids,status FROM attack_graph_progress WHERE agent_id=$1 AND trap_id=$2 AND session_key=$3 AND technique_id=$4 FOR UPDATE")
            .bind(agent_id).bind(event.trap_id).bind(&action.session_key).bind(node.technique_id)
            .fetch_optional(&mut **tx).await?;
        let mut active: Vec<Uuid> = prior.as_ref().map(|r| r.get("active_nodes")).unwrap_or_default();
        let mut evidence: Vec<Uuid> = prior.as_ref().map(|r| r.get("evidence_event_ids")).unwrap_or_default();
        let previous_status: Option<String> = prior.as_ref().map(|r| r.get("status"));
        let reachable = if node.is_start {
            true
        } else if active.is_empty() {
            false
        } else {
            sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM attack_graph_edges WHERE from_node=ANY($1) AND to_node=$2)")
                .bind(&active).bind(node.id).fetch_one(&mut **tx).await?
        };
        // A first observation can begin midway through a known path. Keep it as
        // a candidate subgraph so the next event can extend it without loading
        // or rescanning the entire history.
        if !reachable && !active.is_empty() { continue; }
        if !active.contains(&node.id) { active.push(node.id); }
        if !evidence.contains(&event.event_id) { evidence.push(event.event_id); }
        let confirmed = node.evidence_level == "confirmed" && action.outcome == "confirmed"
            && previous_status.as_deref() == Some("attempt");
        let status = if confirmed { "confirmed" } else if active.len() > 1 { "attempt" } else { "candidate" };
        let similarity = (active.len() as f32 / node.node_count.max(1) as f32).min(1.0);
        sqlx::query("INSERT INTO attack_graph_progress(agent_id,trap_id,session_key,technique_id,active_nodes,evidence_event_ids,status,similarity) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(agent_id,trap_id,session_key,technique_id) DO UPDATE SET active_nodes=EXCLUDED.active_nodes,evidence_event_ids=EXCLUDED.evidence_event_ids,status=CASE WHEN attack_graph_progress.status='confirmed' THEN 'confirmed' ELSE EXCLUDED.status END,similarity=GREATEST(attack_graph_progress.similarity,EXCLUDED.similarity),updated_at=now()")
            .bind(agent_id).bind(event.trap_id).bind(&action.session_key).bind(node.technique_id)
            .bind(&active).bind(&evidence).bind(status).bind(similarity).execute(&mut **tx).await?;
    }

    if touched_techniques.is_empty() && (action.kind.starts_with("boundary.") || action.resource != "other") {
        let suggestion: Option<Uuid> = sqlx::query_scalar("SELECT COALESCE((SELECT technique_id FROM attack_graph_nodes WHERE resource_class=$1 OR action_kind=$2 ORDER BY (resource_class=$1) DESC LIMIT 1),(SELECT technique_id FROM attack_techniques WHERE technique_key='container.escape'))")
            .bind(&action.resource).bind(&action.kind).fetch_optional(&mut **tx).await?;
        sqlx::query("INSERT INTO attack_graph_proposals(proposal_id,action_kind,process_class,resource_class,outcome,sample_event_id,suggested_technique) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(action_kind,process_class,resource_class,outcome) DO UPDATE SET evidence_count=attack_graph_proposals.evidence_count+1,last_seen=now(),suggested_technique=COALESCE(attack_graph_proposals.suggested_technique,EXCLUDED.suggested_technique)")
            .bind(Uuid::new_v4()).bind(&action.kind).bind(&action.process).bind(&action.resource)
            .bind(&action.outcome).bind(event.event_id).bind(suggestion).execute(&mut **tx).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(event_type: &str, payload: Value) -> IncomingEvent {
        IncomingEvent {
            event_id: Uuid::new_v4(), trap_id: Uuid::new_v4(), session_id: Some("s1".into()), sequence_no: None,
            event_type: event_type.into(), occurred_at: chrono::Utc::now(), source_ip: None, source_port: None,
            destination_port: None, protocol: "tcp".into(), service_type: "ssh".into(), payload, metadata: json!({}),
        }
    }

    #[test]
    fn normalizes_semantics_and_confirmation_separately() {
        let docker = normalize(&event("command.executed", json!({"command":"podman ps"})));
        assert_eq!(docker.kind, "process.command");
        assert_eq!(docker.resource, "container_runtime");
        let denied = normalize(&event("auth.attempted", json!({"accepted":false})));
        assert_eq!(denied.outcome, "denied");
        let merely_similar = normalize(&event("security.host_exec_from_trap", json!({})));
        assert_eq!(merely_similar.outcome, "observed");
        let confirmed = IncomingEvent { metadata: json!({"assessment":"confirmed"}), ..event("security.escape_confirmed", json!({})) };
        assert_eq!(normalize(&confirmed).outcome, "confirmed");
    }
}
