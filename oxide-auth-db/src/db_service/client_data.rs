use oxide_auth::primitives::prelude::Scope;
use oxide_auth::primitives::registrar::{ClientType, EncodedClient, RegisteredUrl, ExactUrl};
use cdrs::types::prelude::*;
use cdrs::types::from_cdrs::FromCDRSByName;
use cdrs::frame::IntoBytes;

use std::str::FromStr;


/// A client whose credentials have been wrapped by a password policy.
///
/// This provides a standard encoding for `Registrars` who wish to store their clients and makes it
/// possible to test password policies.
#[derive(Clone, Debug, Serialize, Deserialize, IntoCDRSValue, TryFromRow)]
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
        let uris = &self.additional_redirect_uris.unwrap_or_default();
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
            additional_redirect_uris,
            default_scope,
            client_secret,
        }
    }
}