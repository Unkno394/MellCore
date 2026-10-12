//! Control-plane planning for one shared public TCP listener.
//! The API/UI supplies only the desired external port and optional weights.

use std::collections::HashSet;

use hf_core::{AgentCommand, SharedTcpTrapKind, TcpPortGroup, TcpPortGroupMember};
use uuid::Uuid;

pub const INTERNAL_PORT_START: u16 = 31_000;
pub const INTERNAL_PORT_END: u16 = 32_000;

#[derive(Clone, Copy, Debug)]
pub struct GroupCandidate {
    pub trap_id: Uuid,
    pub weight: u8,
    pub trap_kind: SharedTcpTrapKind,
}

/// Allocates loopback ports deterministically from the HoneyForge internal range and creates the
/// single command consumed by the agent. The caller supplies every already allocated backend port
/// for this VPS, including Docker-published ports.
pub fn plan_tcp_port_group(
    listener_port: u16,
    candidates: &[GroupCandidate],
    occupied_backend_ports: &HashSet<u16>,
) -> Result<AgentCommand, &'static str> {
    if listener_port == 0 || candidates.len() < 2 {
        return Err("a shared listener needs a port and at least two traps");
    }
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
        while unavailable.contains(&next) && next < INTERNAL_PORT_END {
            next += 1;
        }
        if next >= INTERNAL_PORT_END {
            return Err("no free internal backend ports remain");
        }
        members.push(TcpPortGroupMember {
            trap_id: candidate.trap_id,
            backend_port: next,
            weight: candidate.weight,
            trap_kind: candidate.trap_kind,
        });
        unavailable.insert(next);
        next += 1;
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
                },
                GroupCandidate {
                    trap_id: second,
                    weight: 50,
                    trap_kind: SharedTcpTrapKind::Kozyavka,
                },
            ],
            &HashSet::from([31_000]),
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
