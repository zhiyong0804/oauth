use crate::primitives::db_registrar::OauthClientDBRepository;
use oxide_auth::primitives::prelude::Scope;
use oxide_auth::primitives::registrar::{ClientType, EncodedClient, RegisteredUrl, ExactUrl};

use redis::{Commands, RedisError, ErrorKind, ConnectionInfo};
use redis::cluster::{ClusterClient as Client, ClusterClientBuilder};

use cdrs::authenticators::StaticPasswordAuthenticator;
use cdrs::cluster::session::{new as new_session, Session};
use cdrs::cluster::{ClusterTcpConfig, NodeTcpConfigBuilder, TcpConnectionPool};
use cdrs::load_balancing::RoundRobin;
use cdrs::query::*;
use cdrs::types::prelude::*;
use cdrs::frame::IntoBytes;
use cdrs::types::from_cdrs::FromCDRSByName;

use std::str::FromStr;
use url::Url;

type CurrentSession = Session<RoundRobin<TcpConnectionPool<StaticPasswordAuthenticator>>>;

/// redis datasource to Client entries.
pub struct DBDataSource {
    scylla_session: CurrentSession,
    redis_client: Client,
    redis_prefix: String,
    db_name: String,
    db_table: String,
}

/// A client whose credentials have been wrapped by a password policy.
///
/// This provides a standard encoding for `Registrars` who wish to store their clients and makes it
/// possible to test password policies.
#[derive(Clone, Debug, IntoCDRSValue, TryFromRow, PartialEq, Default, Serialize, Deserialize)]
pub struct StringfiedEncodedClient {
    /// The id of this client. If this is was registered at a `Registrar`, this should be a key
    /// to the instance.
    pub client_id: String,

    /// The registered redirect uri.
    /// Unlike `additional_redirect_uris`, this is registered as the default redirect uri
    /// and will be replaced if, for example, no `redirect_uri` is specified in the request parameter.
    pub redirect_uri: String,

    /// The redirect uris that can be registered in addition to the `redirect_uri`.
    /// If you want to register multiple redirect uris, register them together with `redirect_uri`.
    pub additional_redirect_uris: Option<Vec<String>>,

    /// The scope the client gets if none was given.
    pub default_scope: Option<String>,

    /// client_secret, for authentication.
    pub client_secret: Option<String>,
}

impl StringfiedEncodedClient {
    pub fn to_encoded_client(&self) -> anyhow::Result<EncodedClient> {
        let redirect_uri = RegisteredUrl::from(ExactUrl::from_str(&self.redirect_uri)?);
        let uris = &self.additional_redirect_uris.clone().unwrap_or_default();
        let additional_redirect_uris = uris.iter().fold(vec![], |mut us, u| {
            us.push(RegisteredUrl::from(ExactUrl::from_str(u).unwrap()));
            us
        });

        let client_type = match &self.client_secret {
            None => ClientType::Public,
            Some(secret) => ClientType::Confidential {
                passdata: secret.to_owned().into_bytes(),
            },
        };

        Ok(EncodedClient {
            client_id: (&self.client_id).parse().unwrap(),
            redirect_uri,
            additional_redirect_uris,
            default_scope: Scope::from_str(
                self.default_scope.as_ref().unwrap_or(&"".to_string()).as_ref(),
            )
                .unwrap(),
            encoded_client: client_type,
        })
    }

    pub fn from_encoded_client(encoded_client: &EncodedClient) -> Self {
        let additional_redirect_uris = encoded_client
            .additional_redirect_uris
            .iter()
            .map(|u| u.to_owned().as_str().parse().unwrap())
            .collect();
        let default_scope = Some(encoded_client.default_scope.to_string());
        let client_secret = match &encoded_client.encoded_client {
            ClientType::Public => None,
            ClientType::Confidential { passdata } => Some(String::from_utf8(passdata.to_vec()).unwrap()),
        };
        StringfiedEncodedClient {
            client_id: encoded_client.client_id.to_owned(),
            redirect_uri: encoded_client.redirect_uri.to_owned().as_str().parse().unwrap(),
            additional_redirect_uris: Some(additional_redirect_uris),
            default_scope,
            client_secret,
        }
    }
}

impl DBDataSource {
    pub fn new(redis_nodes: Vec<&str>, redis_prefix: &str, password: Option<&str>, db_nodes: Vec<&str>, db_user: &str, db_pwd: &str, db_name: &str, db_table: &str) -> anyhow::Result<Self> {

        let client = {
            let mut builder = ClusterClientBuilder::new(redis_nodes);
            if password.is_some() {
                builder = builder.password(password.unwrap_or_default().to_string());
            }
            let client = builder.open()?;
            client
        };

        let session = {
            let auth = StaticPasswordAuthenticator::new(db_user, db_pwd);
            let mut configs = vec![];

            for n in db_nodes {
                let node = NodeTcpConfigBuilder::new(n, auth.clone()).build();
                configs.push(node);
            }
            let session = new_session(&ClusterTcpConfig(configs), RoundRobin::new())?;
            session
        };

        Ok(DBDataSource {
            scylla_session: session,
            redis_client: client,
            redis_prefix: redis_prefix.to_string(),
            db_name: db_name.to_string(),
            db_table: db_table.to_string(),
        })
    }
    pub fn regist_to_cache(&self, detail: &StringfiedEncodedClient) -> anyhow::Result<()> {
        let mut connect = self.redis_client.get_connection()?;
        let client_str = serde_json::to_string(&detail)?;
        connect.set_ex(&(self.redis_prefix.to_owned() + &detail.client_id), client_str, 3600)?;
        Ok(())
    }

}

impl OauthClientDBRepository for DBDataSource {
    fn list(&self) -> anyhow::Result<Vec<EncodedClient>> {
        let mut encoded_clients: Vec<EncodedClient> = vec![];
        let mut r = self.redis_client.get_connection()?;
        let keys = r.keys::<&str, Vec<String>>(&self.redis_prefix)?;
        for key in keys {
            let clients_str = r.get::<String, String>(key)?;
            let stringfied_client = serde_json::from_str::<StringfiedEncodedClient>(&clients_str)?;
            encoded_clients.push(stringfied_client.to_encoded_client()?);
        }
        Ok(encoded_clients)
    }

    fn find_client_by_id(&self, id: &str) -> anyhow::Result<EncodedClient> {
        let mut r = self.redis_client.get_connection()?;
        let client_str = match r.get::<&str, String>(&(self.redis_prefix.to_owned() + id)){
            Ok(v) => {v}
            Err(err) => {
                error!("{}", err.to_string());
                "".to_string()
            }
        };
        if &client_str == ""{
            let smt = format!("SELECT client_id, client_secret, redirect_uri, additional_redirect_uris, scopes as default_scope FROM {}.{} where client_id = ?", self.db_name, self.db_table);
            let r = self.scylla_session.query_with_values(smt, query_values!(id))?
                .get_body()?
                .into_rows().ok_or(anyhow::Error::msg("Record Not Found"))?;
            if r.len() > 0 {
                let b: StringfiedEncodedClient = StringfiedEncodedClient::try_from_row(r.get(0).unwrap().to_owned())?;
                let client = b.to_encoded_client()?;
                self.regist_to_cache(&b)?;
                Ok(client)
            } else {
                Err(anyhow::Error::msg("Not Found"))
            }
        }else{
            let stringfied_client = serde_json::from_str::<StringfiedEncodedClient>(&client_str)?;
            Ok(stringfied_client.to_encoded_client()?)
        }

    }

    fn regist_from_encoded_client(&self, client: EncodedClient) -> anyhow::Result<()> {
        let detail = StringfiedEncodedClient::from_encoded_client(&client);
        self.regist_to_cache(&detail)
    }
}
