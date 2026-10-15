//! Bounded incremental graph matching. Similarity, observed outcome and escape
//! evidence are independent. Virtual Middle commands never establish host access.
use crate::telemetry::IncomingEvent;
use serde_json::{Value, json};
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

const MAX_NODES: usize = 128;
const MAX_EVIDENCE: usize = 64;
const WINDOW_SECONDS: i64 = 1800;

#[derive(Debug)]
struct Action {
    kind: &'static str,
    process: String,
    resource: &'static str,
    outcome: &'static str,
    domain: &'static str,
    session_key: String,
    environment: Value,
    confirmed: bool,
}

fn resource(path: &str) -> &'static str {
    if hf_core::security::container_runtime_socket(path) {
        "container_runtime"
    } else if path == "/etc/shadow"
        || ["/proc", "/sys", "/host"].iter().any(|prefix| {
            path == *prefix
                || path
                    .strip_prefix(*prefix)
                    .is_some_and(|s| s.starts_with('/'))
        })
    {
        "host_sensitive"
    } else {
        "other"
    }
}

fn normalize(event: &IncomingEvent, trusted_center: bool) -> Action {
    let source = event.metadata["source"].as_str().unwrap_or("");
    let kernel = trusted_center
        && source == "hf-agent-ebpf"
        && event.service_type == "host_monitor"
        && event.protocol == "local"
        && matches!(event.payload["trap_tier"].as_str(), Some("low" | "middle"));
    let simulated = source == "pritvoryashka";
    let domain = if kernel {
        "host_observer"
    } else if simulated {
        "simulated"
    } else {
        "unverified"
    };
    let confirmed = kernel
        && !event.trap_id.is_nil()
        && hf_core::security::confirmed_escape(
            &event.event_type,
            &event.service_type,
            &event.protocol,
            &event.payload,
            &event.metadata,
        );
    let command = event.payload["command"].as_str().unwrap_or("");
    // Exact executable tokens; echo/filenames containing "mount" are not mount operations.
    let executable = command
        .split_whitespace()
        .next()
        .unwrap_or("")
        .rsplit('/')
        .next()
        .unwrap_or("");
    let mut process = "unknown".to_owned();
    let mut resource_class = "other";
    let kind = match event.event_type.as_str() {
        "command.executed" if simulated => {
            process = match executable {
                "docker" | "podman" | "ctr" | "crictl" => {
                    resource_class = "container_runtime";
                    "container_runtime_client"
                }
                "mount" | "unshare" | "nsenter" | "chroot" | "pivot_root" => {
                    resource_class = "namespace_tool";
                    "namespace_utility"
                }
                "sudo" | "su" | "setcap" | "capsh" => "privilege_utility",
                "sh" | "bash" | "dash" | "zsh" => "shell",
                _ => "other_executable",
            }
            .into();
            "process.command"
        }
        "filesystem.accessed" if simulated => {
            process = "virtual_filesystem".into();
            resource_class = resource(event.payload["path"].as_str().unwrap_or(""));
            "filesystem.access"
        }
        "bait.opened" if simulated => {
            process = "virtual_filesystem".into();
            resource_class = "bait_file";
            "deception.bait_open"
        }
        "vulnerability.exploit_attempt" if simulated => {
            process = "virtual_vulnerability".into();
            resource_class = "vulnerability";
            "vulnerability.attempt"
        }
        "security.host_exec_from_trap" if kernel => "boundary.host_exec",
        "security.namespace_mismatch" if kernel => "boundary.namespace_mismatch",
        "security.escape_confirmed" if confirmed => "boundary.escape_confirmed",
        "security.process_exec" | "security.unexpected_executable" if kernel => {
            process = event.payload["exe"]
                .as_str()
                .unwrap_or("unknown")
                .chars()
                .take(256)
                .collect();
            "process.observed"
        }
        "security.policy_violation" if kernel => "policy.violation",
        "security.resource_access" if kernel => {
            process = event.payload["exe"]
                .as_str()
                .unwrap_or("unknown")
                .chars()
                .take(256)
                .collect();
            resource_class = resource(event.payload["resource"].as_str().unwrap_or(""));
            if event.payload["operation"] == "connect" {
                resource_class = "network_unspecified";
                "network.connect"
            } else {
                "resource.open"
            }
        }
        "auth.attempted" | "auth.succeeded" | "auth.failed" => "identity.authentication",
        "connection" | "connection.opened" | "connection.closed" => "network.connection",
        "session.started" | "session.ended" => {
            process = "ssh_service".into();
            resource_class = "session";
            "session.lifecycle"
        }
        _ => "event.other",
    };
    let outcome = if event.event_type == "vulnerability.exploit_attempt" && simulated {
        let details = &event.payload["details"];
        match event
            .payload["accepted"]
            .as_bool()
            .or_else(|| details["accepted"].as_bool())
        {
            Some(true) => "succeeded",
            Some(false) => "denied",
            None => "attempted",
        }
    } else if event.event_type == "bait.opened" && simulated {
        match (
            event.payload["accepted"].as_bool(),
            event.payload["success"].as_bool(),
        ) {
            (Some(true), _) | (None, Some(true)) | (None, None) => "succeeded",
            (Some(false), _) => "denied",
            (None, Some(false)) => "failed",
        }
    } else if confirmed {
        "confirmed"
    } else if kernel && event.event_type == "security.resource_access" {
        match event.payload["outcome"].as_str() {
            Some("succeeded") => "succeeded",
            Some("in_progress") => "attempted",
            Some("denied_or_failed") => "denied",
            _ => "unknown",
        }
    } else if event.payload["accepted"].as_bool() == Some(false)
        || event.event_type == "auth.failed"
    {
        "denied"
    } else if event.payload["exit_status"]
        .as_i64()
        .is_some_and(|v| v != 0)
    {
        "failed"
    } else if event.payload["exit_status"].as_i64() == Some(0)
        || event.payload["accepted"].as_bool() == Some(true)
        || event.event_type == "auth.succeeded"
    {
        "succeeded"
    } else {
        "unknown"
    };
    // Scope observer events by boot and process lifetime, never PID alone.
    let scope = if kernel {
        match (
            event.payload["boot_id"].as_str(),
            event.payload["pid"].as_u64(),
            event.payload["start_ticks"].as_u64(),
        ) {
            (Some(boot), Some(pid), Some(start))
                if Uuid::parse_str(boot).is_ok() && pid > 0 && start > 0 =>
            {
                format!("process:{boot}:{pid}:{start}")
            }
            _ => format!("event:{}", event.event_id),
        }
    } else {
        event
            .session_id
            .as_ref()
            .map(|s| format!("session:{s}"))
            .unwrap_or_else(|| format!("event:{}", event.event_id))
    };
    Action {
        kind,
        process,
        resource: resource_class,
        outcome,
        domain,
        session_key: format!("{domain}:{scope}"),
        confirmed,
        environment: json!({"evidence_domain":domain,"normalizer_version":3,
            "service_type":event.service_type,"protocol":event.protocol,
            "destination_port":event.destination_port,"source":source,
            "subject":event.payload.get("subject"),
            "container_id":event.payload.get("container_id"),
            "operation":event.payload.get("operation"),"policy_decision":event.payload.get("policy_decision"),
            "resource":event.payload.get("resource"),"outcome":event.payload.get("outcome"),
            "cgroup":event.payload.get("cgroup"),"pid_namespace":event.payload.get("pid_namespace"),
            "mount_namespace":event.payload.get("mount_namespace"),"boot_id":event.payload.get("boot_id"),
            "pid":event.payload.get("pid"),"start_ticks":event.payload.get("start_ticks"),
            "bait_id":event.payload.get("bait_id"),"bait_name":event.payload.get("bait_name"),
            "bait_kind":event.payload.get("bait_kind"),
            "bait_path":event.payload.get("path"),
            "vulnerability_profile_id":event.payload.get("profile_id")}),
    }
}

/// State is a bounded set of already matched nodes (subsequence matching). Repeated
/// actions cannot inflate coverage. This score is graph coverage, not a probability.
fn extend(active: &mut Vec<Uuid>, evidence: &mut Vec<Uuid>, node: Uuid, event: Uuid) {
    if !active.contains(&node) && active.len() < MAX_NODES {
        active.push(node);
    }
    if !evidence.contains(&event) {
        if evidence.len() >= MAX_EVIDENCE {
            evidence.remove(0);
        }
        evidence.push(event);
    }
}

pub async fn observe(
    tx: &mut Transaction<'_, Postgres>,
    agent_id: Uuid,
    server_id: Uuid,
    event: &IncomingEvent,
    trusted_center: bool,
) -> Result<(), sqlx::Error> {
    let action = normalize(event, trusted_center);
    debug_assert_eq!(
        action.session_key.split_once(':').map(|(domain, _)| domain),
        Some(action.domain)
    );
    let inserted = sqlx::query("INSERT INTO normalized_attack_actions(event_id,agent_id,server_id,trap_id,session_key,action_kind,process_class,resource_class,outcome,environment) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT(event_id) DO NOTHING")
        .bind(event.event_id).bind(agent_id).bind(server_id).bind(event.trap_id).bind(&action.session_key)
        .bind(action.kind).bind(&action.process).bind(action.resource).bind(action.outcome).bind(&action.environment)
        .execute(&mut **tx).await?.rows_affected();
    if inserted == 0 {
        return Ok(());
    }
    let nodes = sqlx::query(r#"
        SELECT n.node_id,n.technique_id,
          NOT EXISTS(SELECT 1 FROM attack_graph_edges e WHERE e.to_node=n.node_id) AS is_start,
          (SELECT count(*) FROM attack_graph_nodes alln WHERE alln.technique_id=n.technique_id) AS node_count
        FROM attack_graph_nodes n JOIN attack_techniques t USING(technique_id)
        WHERE t.status='known' AND n.action_kind=$1
          AND (n.resource_class='*' OR n.resource_class=$2)
          AND (n.expected_outcome='*' OR n.expected_outcome=$3)
          AND (n.process_class='*' OR n.process_class=$4)
        ORDER BY n.technique_id,n.node_id LIMIT 128
    "#).bind(action.kind).bind(action.resource).bind(action.outcome).bind(&action.process).fetch_all(&mut **tx).await?;
    let matched_semantics = !nodes.is_empty();
    for node in nodes {
        let technique: Uuid = node.get("technique_id");
        let node_id: Uuid = node.get("node_id");
        let prior = sqlx::query("SELECT active_nodes,evidence_event_ids,node_evidence,status,last_occurred_at FROM attack_graph_progress WHERE agent_id=$1 AND trap_id=$2 AND session_key=$3 AND technique_id=$4 FOR UPDATE")
            .bind(agent_id).bind(event.trap_id).bind(&action.session_key).bind(technique).fetch_optional(&mut **tx).await?;
        // One event may satisfy several wildcard nodes; count it once per
        // technique so a single syscall cannot invent a multi-step attack.
        if prior.as_ref().is_some_and(|row| {
            row.get::<Vec<Uuid>, _>("evidence_event_ids")
                .contains(&event.event_id)
        }) {
            continue;
        }
        // Preserve the evidence of a confirmed incident; ordinary later actions
        // must not expire its proof while leaving a misleading confirmed label.
        if prior
            .as_ref()
            .is_some_and(|row| row.get::<String, _>("status") == "confirmed")
        {
            continue;
        }
        let previous_time: Option<chrono::DateTime<chrono::Utc>> =
            prior.as_ref().and_then(|r| r.get("last_occurred_at"));
        // Store late events, but don't invent a temporal edge from them. Explicit
        // validated escape evidence remains actionable regardless of arrival order.
        if !action.confirmed && previous_time.is_some_and(|t| event.occurred_at < t) {
            continue;
        }
        let expired = previous_time.is_some_and(|t| {
            event.occurred_at.signed_duration_since(t).num_seconds() > WINDOW_SECONDS
        });
        let mut active: Vec<Uuid> = if expired {
            vec![]
        } else {
            prior
                .as_ref()
                .map(|r| r.get("active_nodes"))
                .unwrap_or_default()
        };
        let mut evidence: Vec<Uuid> = if expired {
            vec![]
        } else {
            prior
                .as_ref()
                .map(|r| r.get("evidence_event_ids"))
                .unwrap_or_default()
        };
        active.truncate(MAX_NODES);
        evidence.truncate(MAX_EVIDENCE);
        let mut node_evidence = if expired {
            json!({})
        } else {
            prior
                .as_ref()
                .map(|r| r.get::<Value, _>("node_evidence"))
                .unwrap_or_else(|| json!({}))
        };
        let parent: Option<Uuid> = sqlx::query_scalar("SELECT from_node FROM attack_graph_edges WHERE from_node=ANY($1) AND to_node=$2 ORDER BY from_node LIMIT 1")
            .bind(&active).bind(node_id).fetch_optional(&mut **tx).await?;
        let reachable =
            node.get::<bool, _>("is_start") || active.contains(&node_id) || parent.is_some();
        if !reachable && !action.confirmed {
            continue;
        }
        if !active.contains(&node_id) {
            node_evidence[node_id.to_string()] = json!({
                "event_id": event.event_id,
                "observed_outcome": action.outcome,
                "occurred_at": event.occurred_at,
                "from_node": parent,
            });
        }
        extend(&mut active, &mut evidence, node_id, event.event_id);
        let status = if action.confirmed {
            "confirmed"
        } else if active.len() > 1 {
            "attempt"
        } else {
            "candidate"
        };
        let coverage =
            (active.len() as f32 / node.get::<i64, _>("node_count").max(1) as f32).min(1.0);
        sqlx::query(r#"INSERT INTO attack_graph_progress(agent_id,trap_id,session_key,technique_id,active_nodes,evidence_event_ids,status,similarity,last_occurred_at,node_evidence)
            VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
            ON CONFLICT(agent_id,trap_id,session_key,technique_id) DO UPDATE SET
            active_nodes=EXCLUDED.active_nodes,evidence_event_ids=EXCLUDED.evidence_event_ids,
            status=CASE WHEN attack_graph_progress.status='confirmed' THEN 'confirmed' ELSE EXCLUDED.status END,
            similarity=EXCLUDED.similarity,last_occurred_at=GREATEST(attack_graph_progress.last_occurred_at,EXCLUDED.last_occurred_at),
            node_evidence=EXCLUDED.node_evidence,updated_at=now()"#)
            .bind(agent_id).bind(event.trap_id).bind(&action.session_key).bind(technique)
            .bind(&active).bind(&evidence).bind(status).bind(coverage).bind(event.occurred_at).bind(&node_evidence).execute(&mut **tx).await?;
    }
    // Ordinary logins/connections are not proposed as new Docker escape variants.
    if !matched_semantics
        && (action.kind.starts_with("boundary.")
            || action.kind == "policy.violation"
            || matches!(
                action.resource,
                "container_runtime" | "namespace_tool" | "host_sensitive"
            ))
    {
        let suggestion: Option<Uuid> = sqlx::query_scalar("SELECT COALESCE((SELECT technique_id FROM attack_graph_nodes WHERE resource_class=$1 AND resource_class<>'*' ORDER BY technique_id LIMIT 1),(SELECT technique_id FROM attack_graph_nodes WHERE action_kind=$2 ORDER BY technique_id LIMIT 1),(SELECT technique_id FROM attack_techniques WHERE technique_key='container.escape' AND $2 LIKE 'boundary.%'))")
            .bind(action.resource).bind(action.kind).fetch_optional(&mut **tx).await?;
        sqlx::query("INSERT INTO attack_graph_proposals(proposal_id,action_kind,process_class,resource_class,outcome,sample_event_id,suggested_technique) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(action_kind,process_class,resource_class,outcome) DO UPDATE SET evidence_count=attack_graph_proposals.evidence_count+1,last_seen=now(),suggested_technique=COALESCE(attack_graph_proposals.suggested_technique,EXCLUDED.suggested_technique)")
            .bind(Uuid::new_v4()).bind(action.kind).bind(&action.process).bind(action.resource).bind(action.outcome)
            .bind(event.event_id).bind(suggestion).execute(&mut **tx).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bait_open_is_normalized_with_identity_for_engagement_analysis() {
        let bait_id = Uuid::new_v4();
        let action = normalize(
            &event(
                "bait.opened",
                json!({"bait_id":bait_id,"bait_name":"Report","path":"/home/admin/Documents/report.txt","operation":"read"}),
            ),
            false,
        );
        assert_eq!(action.kind, "deception.bait_open");
        assert_eq!(action.resource, "bait_file");
        assert_eq!(action.outcome, "succeeded");
        assert_eq!(action.environment["bait_id"], json!(bait_id));
        assert!(!action.confirmed);
    }
    fn event(kind: &str, payload: Value) -> IncomingEvent {
        IncomingEvent {
            event_id: Uuid::new_v4(),
            trap_id: Uuid::new_v4(),
            session_id: Some("s".into()),
            sequence_no: None,
            event_type: kind.into(),
            occurred_at: chrono::Utc::now(),
            source_ip: None,
            source_port: None,
            destination_port: None,
            protocol: "tcp".into(),
            service_type: "ssh".into(),
            payload,
            metadata: json!({"source":"pritvoryashka"}),
        }
    }
    #[test]
    fn simulation_cannot_confirm_escape_and_command_arguments_are_not_execution() {
        let echo = normalize(
            &event(
                "command.executed",
                json!({"command":"echo","input":"echo docker mount"}),
            ),
            true,
        );
        assert_eq!(echo.resource, "other");
        let mount = normalize(
            &event(
                "command.executed",
                json!({"command":"/bin/mount","exit_status":1}),
            ),
            true,
        );
        assert_eq!(mount.resource, "namespace_tool");
        assert_eq!(mount.outcome, "failed");
        assert_eq!(mount.domain, "simulated");
        assert!(!mount.confirmed);
        let fake = normalize(
            &event(
                "security.escape_confirmed",
                json!({"assessment":"confirmed"}),
            ),
            true,
        );
        assert!(!fake.confirmed);
        assert_eq!(fake.kind, "event.other");
    }
    #[test]
    fn actual_resource_paths_and_domains_are_preserved() {
        assert_eq!(resource("/process.txt"), "other");
        assert_eq!(resource("/proc/1/root"), "host_sensitive");
        assert_eq!(resource("/var/run/docker.sock"), "container_runtime");
        let mut e = event(
            "security.namespace_mismatch",
            json!({"pid":20,"start_ticks":10,"boot_id":Uuid::new_v4(),"trap_tier":"low"}),
        );
        e.protocol = "local".into();
        e.service_type = "host_monitor".into();
        e.metadata = json!({"source":"hf-agent-ebpf"});
        let first = normalize(&e, true);
        e.payload["start_ticks"] = json!(11);
        assert_ne!(first.session_key, normalize(&e, true).session_key);
        assert_eq!(normalize(&e, false).domain, "unverified");
        e.event_type = "security.resource_access".into();
        e.payload["operation"] = json!("open");
        e.payload["resource"] = json!("/run/docker.sock");
        e.payload["outcome"] = json!("succeeded");
        let open = normalize(&e, true);
        assert_eq!(open.kind, "resource.open");
        assert_eq!(open.resource, "container_runtime");
        assert_eq!(open.outcome, "succeeded");
        e.event_type = "security.resource_access".into();
        e.payload["operation"] = json!("connect");
        e.payload["resource"] = json!("network:ipv4:203.0.113.9:443");
        e.payload["outcome"] = json!("in_progress");
        let connect = normalize(&e, true);
        assert_eq!(connect.kind, "network.connect");
        assert_eq!(connect.resource, "network_unspecified");
        assert_eq!(connect.outcome, "attempted");
        assert_eq!(
            connect.environment["resource"],
            "network:ipv4:203.0.113.9:443"
        );
    }
    #[test]
    fn repetition_does_not_increase_coverage_and_evidence_is_bounded() {
        let node = Uuid::new_v4();
        let mut active = vec![];
        let mut evidence = vec![];
        for _ in 0..1000 {
            extend(&mut active, &mut evidence, node, Uuid::new_v4());
        }
        assert_eq!(active.len(), 1);
        assert_eq!(evidence.len(), MAX_EVIDENCE);
    }
    #[test]
    fn middle_privilege_commands_are_simulations_not_host_compromise() {
        for command in ["sudo id", "id", "cat /etc/shadow"] {
            let action = normalize(
                &event(
                    "command.executed",
                    json!({"command":command,
                "input":command,"exit_status":0}),
                ),
                true,
            );
            assert_eq!(action.domain, "simulated");
            assert!(!action.confirmed);
            assert_ne!(action.kind, "boundary.escape_confirmed");
        }
        let file = normalize(
            &event(
                "filesystem.accessed",
                json!({"operation":"read",
            "path":"/etc/shadow"}),
            ),
            true,
        );
        assert_eq!(file.domain, "simulated");
        assert!(!file.confirmed);
    }
    #[test]
    fn boot_id_and_process_birth_both_scope_host_actions() {
        let mut e = event(
            "security.process_exec",
            json!({"pid":42,"start_ticks":100,
            "boot_id":Uuid::new_v4(),"trap_tier":"middle"}),
        );
        e.protocol = "local".into();
        e.service_type = "host_monitor".into();
        e.metadata = json!({"source":"hf-agent-ebpf"});
        let first = normalize(&e, true).session_key;
        e.payload["start_ticks"] = json!(101);
        let reused = normalize(&e, true).session_key;
        assert_ne!(first, reused);
        e.payload["start_ticks"] = json!(100);
        e.payload["boot_id"] = json!(Uuid::new_v4());
        assert_ne!(first, normalize(&e, true).session_key);
    }
    #[test]
    fn bounded_evidence_keeps_confirming_event() {
        let mut active = vec![];
        let mut evidence = vec![];
        for _ in 0..MAX_EVIDENCE {
            extend(&mut active, &mut evidence, Uuid::new_v4(), Uuid::new_v4());
        }
        let first = evidence[0];
        let incident = Uuid::new_v4();
        extend(&mut active, &mut evidence, Uuid::new_v4(), incident);
        assert_eq!(evidence.len(), MAX_EVIDENCE);
        assert!(!evidence.contains(&first));
        assert_eq!(evidence.last(), Some(&incident));
    }
}
