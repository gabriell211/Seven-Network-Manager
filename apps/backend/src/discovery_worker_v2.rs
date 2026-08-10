use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use ipnet::IpNet;
use serde_json::{Value, json};
use snm_discovery_core::{
    CancellationToken, DiscoveryError, DiscoveryRunPlan, ProbeExecutor,
    incremental::{IncrementalDiscoveryOrchestrator, ProbeResultSink},
};
use snm_discovery_store::{DiscoveryRunView, DiscoveryStore, RunExecutionInput};
use snm_domain::{
    ActionId, ActorId, CorrelationId, ExecutionContext, ExecutionStatus, OrganizationId,
    RoutingDomainId, SiteId,
    discovery::{DiscoveryProbeRequest, DiscoveryProbeResult, DiscoveryStatus, ProbeEvidence},
    inventory::{DeviceType, IdentifierKind},
    ipam::{AddressState, is_ipv6_link_local},
};
use snm_fingerprint_core::{OuiRegistry, classify};
use snm_fingerprint_store::{
    ConfirmedFingerprintFacts, FingerprintStore, SuggestionContext,
};
use snm_inventory_store::{
    DeviceObservation, DeviceView, InventoryQuery, InventoryStore,
    MutationContext as InventoryMutationContext, NewIdentifier,
};
use snm_ipam_store::{
    AddressQuery, IpamError, IpamStore, MutationContext as IpamMutationContext, NewIpAddress,
};
use snm_security::audit::AuditActorType;
use sqlx::PgPool;
use tokio::{task::JoinHandle, time::sleep};
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::runtime_client::{RuntimePort, runtime_failure_result};

#[derive(Clone)]
pub(crate) struct DiscoveryWorker {
    store: DiscoveryStore,
    runtime: Arc<dyn RuntimePort>,
    inventory: InventoryStore,
    ipam: IpamStore,
    fingerprints: FingerprintStore,
    oui: Arc<OuiRegistry>,
    database: PgPool,
}

impl DiscoveryWorker {
    pub(crate) fn new(
        store: DiscoveryStore,
        runtime: Arc<dyn RuntimePort>,
        inventory: InventoryStore,
        ipam: IpamStore,
        fingerprints: FingerprintStore,
        oui: OuiRegistry,
        database: PgPool,
    ) -> Self {
        Self {
            store,
            runtime,
            inventory,
            ipam,
            fingerprints,
            oui: Arc::new(oui),
            database,
        }
    }

    pub(crate) fn spawn(self) -> JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                if let Err(error) = snm_discovery_store::schedule::enqueue_due_scheduled_runs(
                    &self.database,
                    25,
                )
                .await
                {
                    error!(%error, "failed to enqueue scheduled discovery runs");
                }
                match self.store.claim_next_queued_run(None).await {
                    Ok(Some(input)) => {
                        let run_id = input.run.id;
                        if let Err(error) = self.execute_run(input).await {
                            error!(%error, %run_id, "discovery run worker failed");
                            let _ = self
                                .store
                                .finish_run(
                                    run_id,
                                    DiscoveryStatus::Failed,
                                    json!({"workerError": error}),
                                    Some("worker_error"),
                                )
                                .await;
                        }
                    }
                    Ok(None) => sleep(Duration::from_millis(350)).await,
                    Err(error) => {
                        error!(%error, "failed to claim queued discovery run");
                        sleep(Duration::from_secs(1)).await;
                    }
                }
            }
        })
    }

    async fn execute_run(&self, input: RunExecutionInput) -> Result<(), String> {
        let run = &input.run;
        let context = ExecutionContext {
            organization_id: OrganizationId(run.organization_id),
            site_id: SiteId(run.site_id),
            routing_domain_id: RoutingDomainId(run.routing_domain_id),
            actor_id: ActorId(run.requested_by.unwrap_or(Uuid::nil())),
            correlation_id: CorrelationId(run.correlation_id),
            action_id: ActionId(run.id),
            idempotency_key: Some(format!("discovery-run:{}", run.id)),
        };
        let plan = match DiscoveryRunPlan::from_scope(
            context,
            &input.scope.domain_scope(),
            input.scope.execution_scope(),
            &run.seed_targets,
            &input.scope.tcp_ports,
            Some(input.scope.max_targets as usize),
        ) {
            Ok(plan) => plan,
            Err(error) => {
                self.store
                    .finish_run(
                        run.id,
                        DiscoveryStatus::Failed,
                        json!({"planningError": error.to_string()}),
                        Some("planning_error"),
                    )
                    .await
                    .map_err(|store_error| store_error.to_string())?;
                return Ok(());
            }
        };
        self.store
            .set_progress_total(run.id, plan.planned_probe_count())
            .await
            .map_err(|error| error.to_string())?;

        let cancellation = CancellationToken::new();
        let watcher = spawn_cancellation_watch(self.store.clone(), run.id, cancellation.clone());
        let outcome = IncrementalDiscoveryOrchestrator::new(
            Arc::new(RuntimeProbeExecutor {
                runtime: self.runtime.clone(),
            }),
            Arc::new(StoreResultSink {
                store: self.store.clone(),
                run_id: run.id,
            }),
        )
        .execute(plan, cancellation)
        .await;
        watcher.abort();

        let cancellation_requested = self
            .store
            .cancellation_requested(run.id)
            .await
            .unwrap_or(false);
        let reconciliation = self.reconcile(run, &outcome.results).await;
        let mut terminal_status = outcome.status;
        let mut summary = serde_json::to_value(&outcome.summary).unwrap_or_else(|_| json!({}));
        if let Err(reconciliation_error) = reconciliation {
            if terminal_status == DiscoveryStatus::Completed {
                terminal_status = if outcome.summary.evidence_count > 0 {
                    DiscoveryStatus::Partial
                } else {
                    DiscoveryStatus::Failed
                };
            }
            merge_summary(
                &mut summary,
                "reconciliationError",
                json!(reconciliation_error),
            );
        }
        if outcome.summary.orchestration_errors > 0 && !cancellation_requested {
            terminal_status = if outcome.summary.evidence_count > 0 {
                DiscoveryStatus::Partial
            } else {
                DiscoveryStatus::Failed
            };
            merge_summary(
                &mut summary,
                "orchestrationFailure",
                json!("incremental persistence or task execution failed"),
            );
        }
        self.store
            .finish_run(run.id, terminal_status, summary, None)
            .await
            .map_err(|error| error.to_string())?;
        info!(run_id = %run.id, status = terminal_status.as_str(), "discovery run finished");
        Ok(())
    }

    async fn reconcile(
        &self,
        run: &DiscoveryRunView,
        results: &[DiscoveryProbeResult],
    ) -> Result<(), String> {
        let hosts = collect_host_observations(results);
        let prefixes = self
            .ipam
            .list_prefixes(run.organization_id, run.site_id, Some(run.routing_domain_id))
            .await
            .map_err(|error| error.to_string())?;
        let parsed_prefixes = prefixes
            .iter()
            .filter_map(|prefix| {
                prefix
                    .prefix
                    .parse::<IpNet>()
                    .ok()
                    .map(|network| (prefix, network))
            })
            .collect::<Vec<_>>();

        let mut warnings = Vec::new();
        for (address, host) in hosts {
            if !host.observed {
                continue;
            }
            if !is_ipv6_link_local(address)
                && let Some((prefix, _)) = parsed_prefixes
                    .iter()
                    .find(|(_, network)| network.contains(&address))
                && let Err(error) = self
                    .ensure_ipam_observation(run, prefix.id, address, host.hostname.clone())
                    .await
            {
                warnings.push(error);
            }

            let device = if let Some(mac) = host.mac.clone() {
                match self.reconcile_inventory_host(run, &host, mac.clone()).await {
                    Ok(()) => match self.find_device_by_mac(run, &mac).await {
                        Ok(device) => device,
                        Err(error) => {
                            warnings.push(error);
                            None
                        }
                    },
                    Err(error) => {
                        warnings.push(error);
                        None
                    }
                }
            } else {
                None
            };

            if let Err(error) = self
                .persist_fingerprint_suggestions(run, address, &host, device.as_ref())
                .await
            {
                warnings.push(error);
            }
        }
        if warnings.is_empty() {
            Ok(())
        } else {
            Err(warnings.join("; "))
        }
    }

    async fn ensure_ipam_observation(
        &self,
        run: &DiscoveryRunView,
        prefix_id: Uuid,
        address: IpAddr,
        hostname: Option<String>,
    ) -> Result<(), String> {
        let address_text = address.to_string();
        let existing = self
            .ipam
            .list_addresses(
                run.organization_id,
                run.site_id,
                AddressQuery {
                    routing_domain_id: Some(run.routing_domain_id),
                    prefix_id: Some(prefix_id),
                    state: None,
                    search: Some(address_text.clone()),
                    limit: 200,
                    offset: 0,
                },
            )
            .await
            .map_err(|error| error.to_string())?;
        if existing.iter().any(|item| item.address == address_text) {
            return Ok(());
        }
        let context = IpamMutationContext {
            organization_id: run.organization_id,
            site_id: run.site_id,
            actor_type: AuditActorType::System,
            actor_id: None,
            session_id: None,
            source_ip: None,
            request_id: format!("discovery-ipam-{}", run.id),
            correlation_id: run.correlation_id,
        };
        match self
            .ipam
            .create_address(
                &context,
                NewIpAddress {
                    routing_domain_id: run.routing_domain_id,
                    prefix_id,
                    device_id: None,
                    interface_id: None,
                    address: address_text,
                    dns_name: hostname,
                    state: AddressState::Observed,
                    source: "discovery".to_owned(),
                    description: Some(format!("Observed by discovery run {}", run.id)),
                },
            )
            .await
        {
            Ok(_) | Err(IpamError::AddressConflict) => Ok(()),
            Err(error) => Err(error.to_string()),
        }
    }

    async fn reconcile_inventory_host(
        &self,
        run: &DiscoveryRunView,
        host: &HostObservation,
        mac: String,
    ) -> Result<(), String> {
        let context = InventoryMutationContext {
            organization_id: run.organization_id,
            site_id: run.site_id,
            actor_type: AuditActorType::System,
            actor_id: None,
            session_id: None,
            source_ip: None,
            request_id: format!("discovery-inventory-{}", run.id),
            correlation_id: run.correlation_id,
        };
        let mut identifiers = vec![NewIdentifier {
            kind: IdentifierKind::Mac,
            value: mac,
            source: "discovery.arp".to_owned(),
            confidence: Some(1.0),
        }];
        if let Some(hostname) = host.hostname.clone() {
            identifiers.push(NewIdentifier {
                kind: IdentifierKind::Hostname,
                value: hostname,
                source: "discovery.reverse_dns".to_owned(),
                confidence: Some(0.65),
            });
        }
        self.inventory
            .reconcile_observation(
                &context,
                DeviceObservation {
                    device_type: DeviceType::Unknown,
                    display_name: None,
                    hostname: host.hostname.clone(),
                    vendor: None,
                    model: None,
                    os_name: None,
                    os_version: None,
                    firmware_version: None,
                    capabilities: host
                        .open_ports
                        .iter()
                        .map(|port| format!("tcp.port.{port}"))
                        .collect(),
                    identifiers,
                    observed_at: host.last_seen,
                },
            )
            .await
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    async fn find_device_by_mac(
        &self,
        run: &DiscoveryRunView,
        mac: &str,
    ) -> Result<Option<DeviceView>, String> {
        let devices = self
            .inventory
            .list(
                run.organization_id,
                run.site_id,
                InventoryQuery {
                    search: Some(mac.to_owned()),
                    lifecycle: None,
                    device_type: None,
                    limit: 10,
                    offset: 0,
                },
            )
            .await
            .map_err(|error| error.to_string())?;
        Ok(devices.into_iter().next())
    }

    async fn persist_fingerprint_suggestions(
        &self,
        run: &DiscoveryRunView,
        address: IpAddr,
        host: &HostObservation,
        device: Option<&DeviceView>,
    ) -> Result<(), String> {
        let classification = classify(&host.evidence, &self.oui).map_err(|error| error.to_string())?;
        if classification.suggestions.is_empty() {
            return Ok(());
        }
        let confirmed = device.map_or_else(ConfirmedFingerprintFacts::default, |device| {
            ConfirmedFingerprintFacts {
                device_type: (device.device_type != DeviceType::Unknown)
                    .then(|| device.device_type.as_str().to_owned()),
                vendor: device.vendor.clone(),
                os_family: device.os_name.clone(),
                hostname: device.hostname.clone(),
            }
        });
        self.fingerprints
            .upsert_suggestions(
                SuggestionContext {
                    discovery_run_id: run.id,
                    organization_id: run.organization_id,
                    site_id: run.site_id,
                    routing_domain_id: run.routing_domain_id,
                    address,
                    device_id: device.map(|value| value.id),
                },
                &confirmed,
                &classification.suggestions,
            )
            .await
            .map(|_| ())
            .map_err(|error| error.to_string())
    }
}

#[derive(Clone)]
struct RuntimeProbeExecutor {
    runtime: Arc<dyn RuntimePort>,
}

#[async_trait]
impl ProbeExecutor for RuntimeProbeExecutor {
    async fn execute(
        &self,
        request: DiscoveryProbeRequest,
    ) -> Result<DiscoveryProbeResult, DiscoveryError> {
        match self.runtime.discovery_probe(request.clone()).await {
            Ok(result) => Ok(result),
            Err(error) => Ok(runtime_failure_result(&request, &error)),
        }
    }
}

#[derive(Clone)]
struct StoreResultSink {
    store: DiscoveryStore,
    run_id: Uuid,
}

#[async_trait]
impl ProbeResultSink for StoreResultSink {
    async fn record(&self, result: &DiscoveryProbeResult) -> Result<(), DiscoveryError> {
        self.store
            .record_probe_result(self.run_id, result)
            .await
            .map(|_| ())
            .map_err(|error| DiscoveryError::ProbeExecution(error.to_string()))
    }
}

fn spawn_cancellation_watch(
    store: DiscoveryStore,
    run_id: Uuid,
    cancellation: CancellationToken,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            sleep(Duration::from_millis(150)).await;
            match store.cancellation_requested(run_id).await {
                Ok(true) => {
                    cancellation.cancel();
                    break;
                }
                Ok(false) => {}
                Err(error) => {
                    warn!(%error, %run_id, "cancellation watcher failed closed");
                    cancellation.cancel();
                    break;
                }
            }
        }
    })
}

#[derive(Debug, Default)]
struct HostObservation {
    mac: Option<String>,
    hostname: Option<String>,
    open_ports: BTreeSet<u16>,
    evidence: Vec<ProbeEvidence>,
    last_seen: Option<DateTime<Utc>>,
    observed: bool,
}

fn collect_host_observations(results: &[DiscoveryProbeResult]) -> BTreeMap<IpAddr, HostObservation> {
    let mut hosts = BTreeMap::new();
    for result in results {
        if !matches!(
            result.status,
            ExecutionStatus::Succeeded | ExecutionStatus::Partial
        ) {
            continue;
        }
        let host = hosts
            .entry(result.target.address)
            .or_insert_with(HostObservation::default);
        host.observed = true;
        if let Some(port) = result.port
            && result.status == ExecutionStatus::Succeeded
        {
            host.open_ports.insert(port);
        }
        for item in &result.evidence {
            host.evidence.push(item.clone());
            host.last_seen = Some(
                host.last_seen
                    .map_or(item.observed_at, |current| current.max(item.observed_at)),
            );
            match item.field.as_str() {
                "mac" if item.confidence >= 0.95 => host.mac = Some(item.value.clone()),
                "hostname" if item.confidence >= 0.5 => {
                    host.hostname = Some(item.value.clone())
                }
                _ => {}
            }
        }
    }
    hosts
}

fn merge_summary(summary: &mut Value, key: &str, value: Value) {
    if let Some(object) = summary.as_object_mut() {
        object.insert(key.to_owned(), value);
    }
}
