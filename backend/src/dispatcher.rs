//! Control-plane planning for one shared public TCP listener.
//! The API/UI supplies only the desired external port and optional weights.

use std::collections::{HashMap, HashSet};

use hf_core::{AgentCommand, SharedTcpTrapKind, TcpPortGroup, TcpPortGroupMember};
use uuid::Uuid;

pub const INTERNAL_PORT_START: u16 = 31_000;
pub const INTERNAL_PORT_END: u16 = 32_000;

#[derive(Clone, Debug)]
pub struct GroupCandidate {
    pub trap_id: Uuid,
    pub weight: u8,
    pub trap_kind: SharedTcpTrapKind,
    pub service_type: String,
}

pub fn compatible_ssh_trap_kind(
    service_type: &str,
    honeypot_type: &str,
    level: crate::models::TrapLevel,
) -> Option<SharedTcpTrapKind> {
    if service_type != "ssh" {
        return None;
    }
    match (honeypot_type, level) {
        ("kozyavka", crate::models::TrapLevel::Low) => Some(SharedTcpTrapKind::Kozyavka),
        ("pritvoryashka", crate::models::TrapLevel::Medium) => {
            Some(SharedTcpTrapKind::Pritvoryashka)
        }
        _ => None,
    }
}

/// Shared listeners are currently SSH-only. Keep this check in the planner as well as the API
/// boundary so a future caller cannot accidentally create a mixed-protocol endpoint.
pub fn validate_group_compatibility(candidates: &[GroupCandidate]) -> Result<(), &'static str> {
    let Some(first) = candidates.first() else {
        return Err("a shared listener needs at least one trap");
    };
    if first.service_type != "ssh" {
        return Err("shared TCP listeners currently support SSH traps only");
    }
    if candidates
        .iter()
        .any(|candidate| candidate.service_type != first.service_type)
    {
        return Err("traps sharing an endpoint must use the same application protocol");
    }
    Ok(())
}

/// Allocates loopback ports deterministically from the HoneyForge internal range and creates the
/// single command consumed by the agent. The caller supplies every already allocated backend port
/// for this VPS, including Docker-published ports. Existing members keep their backend port
/// so adding another trap does not unnecessarily move a live listener.
pub fn plan_tcp_port_group(
    listener_port: u16,
    candidates: &[GroupCandidate],
    occupied_backend_ports: &HashSet<u16>,
    existing_backend_ports: &HashMap<Uuid, u16>,
) -> Result<AgentCommand, &'static str> {
    if listener_port == 0 || candidates.is_empty() {
        return Err("a shared listener needs a port and at least one trap");
    }
    validate_group_compatibility(candidates)?;
    if candidates
        .iter()
        .map(|candidate| u16::from(candidate.weight))
        .sum::<u16>()
        != 100
        || candidates.iter().any(|candidate| candidate.weight == 0)
    {
        return Err("dispatcher group weights must total exactly 100");
    }
    let mut unique = HashSet::new();
    if candidates
        .iter()
        .any(|candidate| !unique.insert(candidate.trap_id))
    {
        return Err("a trap appears more than once in the dispatcher group");
    }
    let mut unavailable = occupied_backend_ports.clone();
    unavailable.insert(listener_port);
    let mut next = INTERNAL_PORT_START;
    let mut members = Vec::with_capacity(candidates.len());
    for candidate in candidates {
        let backend_port = if let Some(&port) = existing_backend_ports.get(&candidate.trap_id) {
            if port == 0 || port == listener_port {
                return Err("existing dispatcher backend port is invalid");
            }
            port
        } else {
            while unavailable.contains(&next) && next < INTERNAL_PORT_END {
                next += 1;
            }
            if next >= INTERNAL_PORT_END {
                return Err("no free internal backend ports remain");
            }
            next
        };
        members.push(TcpPortGroupMember {
            trap_id: candidate.trap_id,
            backend_port,
            weight: candidate.weight,
            trap_kind: candidate.trap_kind,
        });
        unavailable.insert(backend_port);
        if backend_port == next {
            next += 1;
        }
    }
    Ok(AgentCommand::ReconcileTcpPortGroup(TcpPortGroup {
        command_id: Uuid::new_v4(),
        listener_port,
        members,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_the_same_shared_listener_command_for_the_agent() {
        let first = Uuid::new_v4();
        let second = Uuid::new_v4();
        let command = plan_tcp_port_group(
            1488,
            &[
                GroupCandidate {
                    trap_id: first,
                    weight: 50,
                    trap_kind: SharedTcpTrapKind::Kozyavka,
                    service_type: "ssh".into(),
                },
                GroupCandidate {
                    trap_id: second,
                    weight: 50,
                    trap_kind: SharedTcpTrapKind::Kozyavka,
                    service_type: "ssh".into(),
                },
            ],
            &HashSet::from([31_000]),
            &HashMap::new(),
        )
        .unwrap();
        let AgentCommand::ReconcileTcpPortGroup(group) = command else {
            panic!("wrong command")
        };
        assert_eq!(group.listener_port, 1488);
        assert_eq!(group.members[0].backend_port, 31_001);
        assert_eq!(group.members[1].backend_port, 31_002);
    }
}
