use oxide_auth::primitives::registrar::EncodedClient;
use redis::{Commands, RedisError, ErrorKind, ConnectionInfo};
use redis::cluster::{ClusterClient as Client, ClusterClientBuilder};
use url::Url;

use std::str::FromStr;
use std::time::Duration;

use super::StringfiedEncodedClient;
use crate::primitives::db_registrar::OauthClientDBRepository;



/// redis datasource to Client entries.
#[derive(Clone)]
pub struct RedisClusterDataSource {
    client: Client,
    client_prefix: String,
}


impl RedisClusterDataSource {
    pub fn new(nodes: Vec<String>, password: Option<String>, client_prefix: String) -> Result<Self, RedisError> {
        let mut builder = ClusterClientBuilder::new(nodes);
        if password.is_some() {
            builder = builder.password(password.unwrap_or_default());
        }
        let client = builder.open().map_err(|err|{
            error!("{}", err.to_string());
            err
        })?;
        Ok(RedisClusterDataSource {
            client,
            client_prefix,
        })
    }
}

impl RedisClusterDataSource {
    /// users can regist to redis a custom client struct which can be Serialized and Deserialized.
    pub fn regist(&self, detail: &StringfiedEncodedClient) -> anyhow::Result<()> {
        let mut connect = self.client.get_connection()?;
        let client_str = serde_json::to_string(&detail)?;
        connect.set(&(self.client_prefix.to_owned() + &detail.client_id), client_str)?;
        Ok(())
    }
}

impl OauthClientDBRepository for RedisClusterDataSource {
    fn list(&self) -> anyhow::Result<Vec<EncodedClient>> {
        debug!("list");
        let mut encoded_clients: Vec<EncodedClient> = vec![];
        let mut r = self.client.get_connection()?;
        r.set_read_timeout(Some(Duration::from_secs(5)))?;
        let keys = r.keys::<&str, Vec<String>>(&self.client_prefix)?;
        for key in keys {
            let clients_str = r.get::<String, String>(key)?;
            let stringfied_client = serde_json::from_str::<StringfiedEncodedClient>(&clients_str)?;
            encoded_clients.push(stringfied_client.to_encoded_client()?);
        }
        Ok(encoded_clients)
    }

    fn find_client_by_id(&self, id: &str) -> anyhow::Result<EncodedClient> {
        debug!("find_client_by_id");
        let mut r = self.client.get_connection().unwrap();
        debug!("find_client_by_id");
        r.set_read_timeout(Some(Duration::from_secs(5)))?;
        let client_str = r.get::<&str, String>(&(self.client_prefix.to_owned() + id))?;
        let stringfied_client = serde_json::from_str::<StringfiedEncodedClient>(&client_str).map_err(|err|{
            error!("id={}, client_str={}, error={}", id, client_str, err.to_string());
            err
        })?;
        Ok(stringfied_client.to_encoded_client().map_err(|err|{
            error!("{}", err.to_string());
            err
        })?)
    }

    fn regist_from_encoded_client(&self, client: EncodedClient) -> anyhow::Result<()> {
        let detail = StringfiedEncodedClient::from_encoded_client(&client);
        self.regist(&detail)
    }
}
