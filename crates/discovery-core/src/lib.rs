use std::{
    collections::BTreeSet,
    net::{IpAddr, Ipv4Addr},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use async_trait::async_trait;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use snm_domain::{
    ExecutionContext, ExecutionStatus, ScopedIpTarget,
    discovery::{
        DiscoveryExecutionScope, DiscoveryProbeKind, DiscoveryProbeRequest, DiscoveryProbeResult,
        DiscoveryScope, DiscoveryStatus, Ipv6DiscoveryStrategy, ObservationKind,
    },
};
use thiserror::Error;
use tokio::{
    sync::{Notify, Semaphore},
    task::JoinSet,
    time::sleep,
};

const DEFAULT_MAX_TARGETS: usize = 4096;
const MAX_TCP_PORTS: usize = 64;

#[derive(Clone, Debug)]
pub struct CancellationToken {
    cancelled: Arc<AtomicBool>,
    notify: Arc<Notify>,
}

impl Default for CancellationToken {
    fn default() -> Self {
        Self::new()
    }
}

impl CancellationToken {
    pub fn new() -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
            notify: Arc::new(Notify::new()),
        }
    }

    pub fn cancel(&self) {
        if !self.cancelled.swap(true, Ordering::SeqCst) {
            self.notify.notify_waiters();
        }
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    pub async fn cancelled(&self) {
        if self.is_cancelled() {
            return;
        }
        self.notify.notified().await;
    }
}

#[derive(Debug, Clone)]
pub struct DiscoveryRunPlan {
    pub context: ExecutionContext,
    pub scope: DiscoveryExecutionScope,
    pub observations: Vec<ObservationKind>,
    pub targets: Vec<IpAddr>,
    pub tcp_ports: Vec<u16>,
    pub concurrency_limit: usize,
    pub rate_per_second: u16,
    pub timeout_ms: u64,
}

impl DiscoveryRunPlan {
    pub fn from_scope(
        context: ExecutionContext,
        scope: &DiscoveryScope,
        execution_scope: DiscoveryExecutionScope,
        seeds: &[IpAddr],
        tcp_ports: &[u16],
        max_targets: Option<usize>,
    ) -> Result<Self, DiscoveryError> {
        scope.validate().map_err(DiscoveryError::InvalidScope)?;
        execution_scope
            .validate()
            .map_err(|error| DiscoveryError::InvalidExecutionScope(error.to_string()))?;
        if scope.organization_id != execution_scope.organization_id
            || scope.site_id != execution_scope.site_id
            || scope.routing_domain_id != execution_scope.routing_domain_id
            || scope.network != execution_scope.network
            || context.organization_id != scope.organization_id
            || context.site_id != scope.site_id
            || context.routing_domain_id != scope.routing_domain_id
        {
            return Err(DiscoveryError::ScopeMismatch);
        }

        let targets = plan_targets(
            scope.network,
            scope.ipv6_strategy,
            seeds,
            max_targets.unwrap_or(DEFAULT_MAX_TARGETS),
        )?;
        let ports = normalize_ports(tcp_ports)?;
        if scope.observations.contains(&ObservationKind::Service) && ports.is_empty() {
            return Err(DiscoveryError::TcpPortsRequired);
        }
        if scope
            .observations
            .contains(&ObservationKind::ManagementProtocol)
        {
            return Err(DiscoveryError::UnsupportedObservation(
                ObservationKind::ManagementProtocol,
            ));
        }

        Ok(Self {
            context,
            scope: execution_scope,
            observations: scope.observations.clone(),
            targets,
            tcp_ports: ports,
            concurrency_limit: usize::from(scope.concurrency_limit),
            rate_per_second: scope.rate_per_second,
            timeout_ms: u64::from(scope.timeout_ms),
        })
    }

    pub fn planned_probe_count(&self) -> usize {
        let per_target = self
            .observations
            .iter()
            .map(|kind| match kind {
                ObservationKind::Reachability
                | ObservationKind::Neighbor
                | ObservationKind::ReverseDns => 1,
                ObservationKind::Service => self.tcp_ports.len(),
                ObservationKind::ManagementProtocol => 0,
            })
            .sum::<usize>();
        per_target.saturating_mul(self.targets.len())
    }

    fn requests(&self) -> Vec<DiscoveryProbeRequest> {
        let mut requests = Vec::with_capacity(self.planned_probe_count());
        for address in &self.targets {
            let target = ScopedIpTarget {
                organization_id: self.scope.organization_id,
                site_id: self.scope.site_id,
                routing_domain_id: self.scope.routing_domain_id,
                address: *address,
                interface_scope: if address.is_ipv6() {
                    self.scope.interface_scope.clone()
                } else {
                    None
                },
            };
            for observation in &self.observations {
                match observation {
                    ObservationKind::Reachability => requests.push(self.request(
                        target.clone(),
                        DiscoveryProbeKind::Icmp,
                        None,
                    )),
                    ObservationKind::Neighbor => requests.push(self.request(
                        target.clone(),
                        DiscoveryProbeKind::Arp,
                        None,
                    )),
                    ObservationKind::ReverseDns => requests.push(self.request(
                        target.clone(),
                        DiscoveryProbeKind::ReverseDns,
                        None,
                    )),
                    ObservationKind::Service => {
                        for port in &self.tcp_ports {
                            requests.push(self.request(
                                target.clone(),
                                DiscoveryProbeKind::Tcp,
                                Some(*port),
                            ));
                        }
                    }
                    ObservationKind::ManagementProtocol => {}
                }
            }
        }
        requests
    }

    fn request(
        &self,
        target: ScopedIpTarget,
        probe: DiscoveryProbeKind,
        port: Option<u16>,
    ) -> DiscoveryProbeRequest {
        DiscoveryProbeRequest {
            context: self.context.clone(),
            scope: self.scope.clone(),
            target,
            probe,
            port,
            timeout_ms: self.timeout_ms,
        }
    }
}

#[async_trait]
pub trait ProbeExecutor: Send + Sync {
    async fn execute(
        &self,
        request: DiscoveryProbeRequest,
    ) -> Result<DiscoveryProbeResult, DiscoveryError>;
}

#[derive(Clone)]
pub struct DiscoveryOrchestrator {
    executor: Arc<dyn ProbeExecutor>,
}

impl DiscoveryOrchestrator {
    pub fn new(executor: Arc<dyn ProbeExecutor>) -> Self {
        Self { executor }
    }

    pub async fn execute(
        &self,
        plan: DiscoveryRunPlan,
        cancellation: CancellationToken,
    ) -> DiscoveryRunOutcome {
        let started = Instant::now();
        let total = plan.planned_probe_count();
        let semaphore = Arc::new(Semaphore::new(plan.concurrency_limit.max(1)));
        let launch_delay = Duration::from_secs_f64(1.0 / f64::from(plan.rate_per_second.max(1)));
        let mut tasks = JoinSet::new();

        for request in plan.requests() {
            if cancellation.is_cancelled() {
                break;
            }
            let permit = tokio::select! {
                _ = cancellation.cancelled() => break,
                permit = semaphore.clone().acquire_owned() => match permit {
                    Ok(value) => value,
                    Err(_) => break,
                }
            };
            let executor = self.executor.clone();
            let task_cancellation = cancellation.clone();
            tasks.spawn(async move {
                let _permit = permit;
                let cancelled_result = || DiscoveryProbeResult {
                    status: ExecutionStatus::Cancelled,
                    probe: request.probe,
                    target: request.target.clone(),
                    port: request.port,
                    latency_ms: None,
                    evidence: Vec::new(),
                    error_code: Some("cancelled".to_owned()),
                };
                tokio::select! {
                    _ = task_cancellation.cancelled() => Ok(cancelled_result()),
                    result = executor.execute(request) => result,
                }
            });

            tokio::select! {
                _ = cancellation.cancelled() => break,
                _ = sleep(launch_delay) => {}
            }
        }

        let mut results = Vec::with_capacity(total);
        let mut orchestration_errors = 0_u64;
        while let Some(joined) = tasks.join_next().await {
            match joined {
                Ok(Ok(result)) => results.push(result),
                Ok(Err(_)) | Err(_) => orchestration_errors = orchestration_errors.saturating_add(1),
            }
        }

        results.sort_by_key(|result| {
            (
                result.target.address,
                probe_order(result.probe),
                result.port.unwrap_or(0),
            )
        });
        let summary = RunSummary::from_results(
            total,
            &results,
            orchestration_errors,
            started.elapsed(),
        );
        let status = final_status(&summary, cancellation.is_cancelled());
        DiscoveryRunOutcome {
            status,
            results,
            summary,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RunSummary {
    pub planned: usize,
    pub completed: usize,
    pub succeeded: u64,
    pub failed: u64,
    pub partial: u64,
    pub unknown: u64,
    pub cancelled: u64,
    pub unsupported: u64,
    pub not_applicable: u64,
    pub evidence_count: u64,
    pub orchestration_errors: u64,
    pub duration_ms: u64,
}

impl RunSummary {
    fn from_results(
        planned: usize,
        results: &[DiscoveryProbeResult],
        orchestration_errors: u64,
        duration: Duration,
    ) -> Self {
        let mut summary = Self {
            planned,
            completed: results.len(),
            succeeded: 0,
            failed: 0,
            partial: 0,
            unknown: 0,
            cancelled: 0,
            unsupported: 0,
            not_applicable: 0,
            evidence_count: 0,
            orchestration_errors,
            duration_ms: duration.as_millis().try_into().unwrap_or(u64::MAX),
        };
        for result in results {
            match result.status {
                ExecutionStatus::Succeeded => summary.succeeded += 1,
                ExecutionStatus::Failed => summary.failed += 1,
                ExecutionStatus::Partial => summary.partial += 1,
                ExecutionStatus::Unknown => summary.unknown += 1,
                ExecutionStatus::Cancelled => summary.cancelled += 1,
                ExecutionStatus::Unsupported => summary.unsupported += 1,
                ExecutionStatus::NotApplicable => summary.not_applicable += 1,
            }
            summary.evidence_count = summary
                .evidence_count
                .saturating_add(result.evidence.len().try_into().unwrap_or(u64::MAX));
        }
        summary
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveryRunOutcome {
    pub status: DiscoveryStatus,
    pub results: Vec<DiscoveryProbeResult>,
    pub summary: RunSummary,
}

pub fn plan_targets(
    network: IpNet,
    ipv6_strategy: Option<Ipv6DiscoveryStrategy>,
    seeds: &[IpAddr],
    max_targets: usize,
) -> Result<Vec<IpAddr>, DiscoveryError> {
    if max_targets == 0 || max_targets > 65_536 {
        return Err(DiscoveryError::InvalidTargetLimit);
    }
    let mut unique = BTreeSet::new();
    if !seeds.is_empty() {
        for seed in seeds {
            if !network.contains(seed) {
                return Err(DiscoveryError::SeedOutsideScope(*seed));
            }
            if snm_domain::discovery::is_ipv4_network_or_broadcast(network, *seed) {
                return Err(DiscoveryError::InvalidSeed(*seed));
            }
            unique.insert(*seed);
        }
        if unique.len() > max_targets {
            return Err(DiscoveryError::RangeTooLarge {
                planned: unique.len(),
                max: max_targets,
            });
        }
        return Ok(unique.into_iter().collect());
    }

    match network {
        IpNet::V4(network) => enumerate_ipv4(network, max_targets),
        IpNet::V6(_) => match ipv6_strategy {
            Some(Ipv6DiscoveryStrategy::SeededTargets) | None => {
                Err(DiscoveryError::Ipv6SeedsRequired)
            }
            Some(
                Ipv6DiscoveryStrategy::NeighborEvidence
                | Ipv6DiscoveryStrategy::DnsEvidence
                | Ipv6DiscoveryStrategy::ProviderInventory,
            ) => Err(DiscoveryError::EvidenceStrategyRequiresExternalSeeds),
        },
    }
}

fn enumerate_ipv4(
    network: ipnet::Ipv4Net,
    max_targets: usize,
) -> Result<Vec<IpAddr>, DiscoveryError> {
    let host_bits = 32_u32.saturating_sub(u32::from(network.prefix_len()));
    let total = 1_u64.checked_shl(host_bits).unwrap_or(u64::MAX);
    let usable = if network.prefix_len() >= 31 {
        total
    } else {
        total.saturating_sub(2)
    };
    if usable > max_targets as u64 {
        return Err(DiscoveryError::RangeTooLarge {
            planned: usize::try_from(usable).unwrap_or(usize::MAX),
            max: max_targets,
        });
    }

    let first = u32::from(network.network());
    let last = u32::from(network.broadcast());
    let (start, end) = if network.prefix_len() >= 31 {
        (first, last)
    } else {
        (first.saturating_add(1), last.saturating_sub(1))
    };
    Ok((start..=end)
        .map(|value| IpAddr::V4(Ipv4Addr::from(value)))
        .collect())
}

fn normalize_ports(ports: &[u16]) -> Result<Vec<u16>, DiscoveryError> {
    if ports.len() > MAX_TCP_PORTS {
        return Err(DiscoveryError::TooManyTcpPorts);
    }
    let unique: BTreeSet<u16> = ports.iter().copied().filter(|port| *port > 0).collect();
    if unique.len() != ports.iter().filter(|port| **port > 0).count() {
        // Duplicates are harmless; normalize them instead of multiplying probes.
    }
    Ok(unique.into_iter().collect())
}

fn final_status(summary: &RunSummary, cancelled: bool) -> DiscoveryStatus {
    if cancelled || summary.cancelled > 0 || summary.completed < summary.planned {
        return DiscoveryStatus::Cancelled;
    }
    let hard_failures = summary
        .failed
        .saturating_add(summary.unknown)
        .saturating_add(summary.orchestration_errors);
    let soft_failures = summary
        .partial
        .saturating_add(summary.unsupported)
        .saturating_add(summary.not_applicable);
    if hard_failures == 0 && soft_failures == 0 {
        DiscoveryStatus::Completed
    } else if summary.succeeded > 0 || summary.evidence_count > 0 {
        DiscoveryStatus::Partial
    } else {
        DiscoveryStatus::Failed
    }
}

fn probe_order(probe: DiscoveryProbeKind) -> u8 {
    match probe {
        DiscoveryProbeKind::Icmp => 0,
        DiscoveryProbeKind::Arp => 1,
        DiscoveryProbeKind::ReverseDns => 2,
        DiscoveryProbeKind::Tcp => 3,
    }
}

#[derive(Debug, Error)]
pub enum DiscoveryError {
    #[error("discovery scope is invalid: {0}")]
    InvalidScope(&'static str),
    #[error("discovery execution scope is invalid: {0}")]
    InvalidExecutionScope(String),
    #[error("discovery scope and execution context do not match")]
    ScopeMismatch,
    #[error("target planning limit is invalid")]
    InvalidTargetLimit,
    #[error("planned target count {planned} exceeds maximum {max}")]
    RangeTooLarge { planned: usize, max: usize },
    #[error("IPv6 discovery requires explicit seeded targets")]
    Ipv6SeedsRequired,
    #[error("selected IPv6 evidence strategy requires an external evidence source")]
    EvidenceStrategyRequiresExternalSeeds,
    #[error("seed target {0} is outside the discovery scope")]
    SeedOutsideScope(IpAddr),
    #[error("seed target {0} is a network/broadcast address")]
    InvalidSeed(IpAddr),
    #[error("TCP service discovery requires at least one configured port")]
    TcpPortsRequired,
    #[error("at most 64 TCP ports may be configured per scope")]
    TooManyTcpPorts,
    #[error("observation kind {0:?} is not implemented by the MVP probe pipeline")]
    UnsupportedObservation(ObservationKind),
    #[error("probe execution failed: {0}")]
    ProbeExecution(String),
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use snm_domain::{
        ActionId, ActorId, CorrelationId, OrganizationId, RoutingDomainId, SiteId,
        discovery::{ProbeEvidence, DiscoveryProbeKind},
    };

    use super::*;

    #[derive(Clone)]
    struct FakeExecutor {
        calls: Arc<AtomicUsize>,
        fail_tcp: bool,
        delay: Duration,
    }

    #[async_trait]
    impl ProbeExecutor for FakeExecutor {
        async fn execute(
            &self,
            request: DiscoveryProbeRequest,
        ) -> Result<DiscoveryProbeResult, DiscoveryError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if !self.delay.is_zero() {
                sleep(self.delay).await;
            }
            let failed = self.fail_tcp && request.probe == DiscoveryProbeKind::Tcp;
            Ok(DiscoveryProbeResult {
                status: if failed {
                    ExecutionStatus::Failed
                } else {
                    ExecutionStatus::Succeeded
                },
                probe: request.probe,
                target: request.target,
                port: request.port,
                latency_ms: Some(1),
                evidence: if failed {
                    Vec::new()
                } else {
                    vec![ProbeEvidence {
                        field: "test".into(),
                        value: "ok".into(),
                        source: "fake".into(),
                        confidence: 1.0,
                        observed_at: chrono::Utc::now(),
                    }]
                },
                error_code: failed.then(|| "synthetic_failure".into()),
            })
        }
    }

    fn scope(network: &str, observations: Vec<ObservationKind>) -> (DiscoveryScope, ExecutionContext, DiscoveryExecutionScope) {
        let organization_id = OrganizationId::new();
        let site_id = SiteId::new();
        let routing_domain_id = RoutingDomainId::new();
        let network: IpNet = network.parse().unwrap();
        (
            DiscoveryScope {
                id: uuid::Uuid::now_v7(),
                organization_id,
                site_id,
                routing_domain_id,
                network,
                observations,
                ipv6_strategy: if network.is_ipv6() {
                    Some(Ipv6DiscoveryStrategy::SeededTargets)
                } else {
                    None
                },
                concurrency_limit: 4,
                rate_per_second: 1000,
                timeout_ms: 1000,
            },
            ExecutionContext {
                organization_id,
                site_id,
                routing_domain_id,
                actor_id: ActorId::new(),
                correlation_id: CorrelationId::new(),
                action_id: ActionId::new(),
                idempotency_key: None,
            },
            DiscoveryExecutionScope {
                organization_id,
                site_id,
                routing_domain_id,
                network,
                interface_scope: None,
                source_address: None,
            },
        )
    }

    #[test]
    fn ipv4_planning_skips_network_and_broadcast() {
        let targets = plan_targets("10.0.0.0/30".parse().unwrap(), None, &[], 10).unwrap();
        assert_eq!(targets, vec!["10.0.0.1".parse().unwrap(), "10.0.0.2".parse().unwrap()]);
    }

    #[test]
    fn ipv4_point_to_point_keeps_both_addresses() {
        let targets = plan_targets("10.0.0.0/31".parse().unwrap(), None, &[], 10).unwrap();
        assert_eq!(targets.len(), 2);
    }

    #[test]
    fn large_ipv4_range_requires_explicit_seeds_or_higher_policy_limit() {
        assert!(matches!(
            plan_targets("10.0.0.0/16".parse().unwrap(), None, &[], 4096),
            Err(DiscoveryError::RangeTooLarge { .. })
        ));
    }

    #[test]
    fn ipv6_never_bruteforces_a_prefix() {
        assert!(matches!(
            plan_targets(
                "2001:db8::/64".parse().unwrap(),
                Some(Ipv6DiscoveryStrategy::SeededTargets),
                &[],
                4096
            ),
            Err(DiscoveryError::Ipv6SeedsRequired)
        ));
    }

    #[test]
    fn duplicate_seeds_are_deduplicated() {
        let seed: IpAddr = "2001:db8::10".parse().unwrap();
        let targets = plan_targets(
            "2001:db8::/64".parse().unwrap(),
            Some(Ipv6DiscoveryStrategy::SeededTargets),
            &[seed, seed],
            10,
        )
        .unwrap();
        assert_eq!(targets, vec![seed]);
    }

    #[tokio::test]
    async fn one_failed_probe_preserves_successful_evidence_and_marks_partial() {
        let (scope, context, execution_scope) = scope(
            "10.0.0.0/30",
            vec![ObservationKind::Reachability, ObservationKind::Service],
        );
        let plan = DiscoveryRunPlan::from_scope(
            context,
            &scope,
            execution_scope,
            &[],
            &[443],
            Some(10),
        )
        .unwrap();
        let executor = FakeExecutor {
            calls: Arc::new(AtomicUsize::new(0)),
            fail_tcp: true,
            delay: Duration::ZERO,
        };
        let outcome = DiscoveryOrchestrator::new(Arc::new(executor))
            .execute(plan, CancellationToken::new())
            .await;
        assert_eq!(outcome.status, DiscoveryStatus::Partial);
        assert_eq!(outcome.summary.succeeded, 2);
        assert_eq!(outcome.summary.failed, 2);
        assert_eq!(outcome.summary.evidence_count, 2);
    }

    #[tokio::test]
    async fn cancellation_stops_pending_fanout() {
        let (scope, context, execution_scope) = scope(
            "10.0.0.0/29",
            vec![ObservationKind::Reachability, ObservationKind::ReverseDns],
        );
        let plan = DiscoveryRunPlan::from_scope(
            context,
            &scope,
            execution_scope,
            &[],
            &[],
            Some(20),
        )
        .unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let executor = FakeExecutor {
            calls: calls.clone(),
            fail_tcp: false,
            delay: Duration::from_millis(200),
        };
        let cancellation = CancellationToken::new();
        let cancel_clone = cancellation.clone();
        tokio::spawn(async move {
            sleep(Duration::from_millis(20)).await;
            cancel_clone.cancel();
        });
        let outcome = DiscoveryOrchestrator::new(Arc::new(executor))
            .execute(plan, cancellation)
            .await;
        assert_eq!(outcome.status, DiscoveryStatus::Cancelled);
        assert!(calls.load(Ordering::SeqCst) < 12);
    }
}
