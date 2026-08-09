use redis::{Client, aio::ConnectionManager};

#[derive(Clone)]
pub(crate) struct RedisState {
    manager: ConnectionManager,
}

impl RedisState {
    pub(crate) async fn connect(url: &str) -> redis::RedisResult<Self> {
        let client = Client::open(url)?;
        let manager = ConnectionManager::new(client).await?;
        Ok(Self { manager })
    }

    pub(crate) async fn health(&self) -> redis::RedisResult<()> {
        let mut connection = self.manager.clone();
        let _: String = redis::cmd("PING").query_async(&mut connection).await?;
        Ok(())
    }
}
