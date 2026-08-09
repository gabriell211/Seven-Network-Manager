use anyhow::Result;
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("snm_site_runtime=info,snm_executor_core=info")
        .init();

    info!("Seven Network Manager site runtime started");
    info!("executor-core loaded; providers are registered by capability packages");

    tokio::signal::ctrl_c().await?;
    info!("Seven Network Manager site runtime stopped");
    Ok(())
}
