use crate::primitives::db_registrar::OauthClientDBRepository;
use oxide_auth::primitives::prelude::Scope;
use oxide_auth::primitives::registrar::{ClientType, EncodedClient, RegisteredUrl, ExactUrl};

use cdrs::authenticators::StaticPasswordAuthenticator;
use cdrs::cluster::session::{new as new_session, Session};
use cdrs::cluster::{ClusterTcpConfig, NodeTcpConfigBuilder, TcpConnectionPool};
use cdrs::load_balancing::RoundRobin;
use cdrs::query::*;
use cdrs::types::prelude::*;
use cdrs::frame::IntoBytes;
use cdrs::types::from_cdrs::FromCDRSByName;

use std::str::FromStr;
use std::time::Duration;
use std::borrow::Borrow;

type CurrentSession = Session<RoundRobin<TcpConnectionPool<StaticPasswordAuthenticator>>>;


pub struct DBDataSource {
    session: CurrentSession,
    db_name: String,
    table_name: String,
}


impl DBDataSource {
    pub fn new(nodes: Vec<&str>, username: &str, password: &str, db_name: &str, table_name: &str) -> anyhow::Result<Self> {
        let auth = StaticPasswordAuthenticator::new(username, password);
        let mut configs = vec![];

        for n in nodes {
            let node = NodeTcpConfigBuilder::new(n, auth.clone()).build();
            configs.push(node);
        }
        let session = new_session(&ClusterTcpConfig(configs), RoundRobin::new())?;

        Ok(DBDataSource {
            session,
            db_name: db_name.to_string(),
            table_name: table_name.to_string(),
        })
    }

    pub fn regist(&self, client: EncodedClient) -> anyhow::Result<()> {

        Ok(())
    }
}


impl OauthClientDBRepository for DBDataSource {
    fn list(&self) -> anyhow::Result<Vec<EncodedClient>> {
        Err(anyhow::Error::msg("TODO"))
    }

    fn find_client_by_id(&self, id: &str) -> anyhow::Result<EncodedClient> {
        let smt = format!("SELECT client_id, client_secret, redirect_uri, additional_redirect_uris, scopes as default_scope FROM {}.{} where client_id = ?", self.db_name, self.table_name);
        let r = self.session.query_with_values(smt, query_values!(id))?
            .get_body()?
            .into_rows().ok_or(anyhow::Error::msg("Record Not Found"))?;
        return if r.len() > 0 {
            let b: StringfiedEncodedClient = StringfiedEncodedClient::try_from_row(r.get(0).unwrap().to_owned())?;
            let client = b.to_encoded_client()?;
            Ok(client)
        } else {
            Err(anyhow::Error::msg("Not Found"))
        };
    }

    fn regist_from_encoded_client(&self, client: EncodedClient) -> anyhow::Result<()> {
        self.regist(client)
    }
}

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
    pub fn into_query_values(self) -> QueryValues {
        query_values!(
        "client_id" => self.client_id,
        "redirect_uri" => self.redirect_uri,
        "additional_redirect_uris" => self.additional_redirect_uris,
        "scopes" => self.default_scope,
        "client_secret" => self.client_secret
        )
    }
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