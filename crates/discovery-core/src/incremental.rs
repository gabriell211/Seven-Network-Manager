use std::{sync::Arc, time::{Duration, Instant}};

use async_trait::async_trait;
use snm_domain::discovery::DiscoveryProbeResult;
use tokio::{sync::Semaphore, task::JoinSet, time::sleep};

use crate::{
    CancellationToken, DiscoveryError, DiscoveryProbeRequest, DiscoveryRunOutcome,
    DiscoveryRunPlan, ProbeExecutor, RunSummary, final_status, probe_order,
};

#[async_trait]
pub trait ProbeResultSink: Send + Sync {
    async fn record(&self, result: &DiscoveryProbeResult) -> Result<(), DiscoveryError>;
}

pub struct IncrementalDiscoveryOrchestrator {
    executor: Arc<dyn ProbeExecutor>,
    sink: Arc<dyn ProbeResultSink>,
}

impl IncrementalDiscoveryOrchestrator {
    pub fn new(executor: Arc<dyn ProbeExecutor>, sink: Arc<dyn ProbeResultSink>) -> Self {
        Self { executor, sink }
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
                execute_one(executor, request, task_cancellation).await
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
                Ok(Ok(result)) => {
                    if self.sink.record(&result).await.is_err() {
                        orchestration_errors = orchestration_errors.saturating_add(1);
                        cancellation.cancel();
                    }
                    results.push(result);
                }
                Ok(Err(_)) | Err(_) => {
                    orchestration_errors = orchestration_errors.saturating_add(1);
                    cancellation.cancel();
                }
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
        DiscoveryRunOutcome {
            status: final_status(&summary, cancellation.is_cancelled()),
            results,
            summary,
        }
    }
}

async fn execute_one(
    executor: Arc<dyn ProbeExecutor>,
    request: DiscoveryProbeRequest,
    cancellation: CancellationToken,
) -> Result<DiscoveryProbeResult, DiscoveryError> {
    let cancelled = || DiscoveryProbeResult {
        status: snm_domain::ExecutionStatus::Cancelled,
        probe: request.probe,
        target: request.target.clone(),
        port: request.port,
        latency_ms: None,
        evidence: Vec::new(),
        error_code: Some("cancelled".to_owned()),
    };
    tokio::select! {
        _ = cancellation.cancelled() => Ok(cancelled()),
        result = executor.execute(request) => result,
    }
}
