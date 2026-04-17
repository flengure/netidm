use crate::{ClientError, KanidmClient};
use kanidm_proto::wg::{
    WgConnectRequest, WgConnectResponse, WgPeerResponse, WgTokenCreate, WgTokenCreatedResponse,
    WgTokenInfo, WgTunnelCreate, WgTunnelResponse,
};

impl KanidmClient {
    pub async fn wg_tunnel_list(&self) -> Result<Vec<WgTunnelResponse>, ClientError> {
        self.perform_get_request("/v1/wg/tunnel").await
    }

    pub async fn wg_tunnel_get(
        &self,
        name: &str,
    ) -> Result<Option<WgTunnelResponse>, ClientError> {
        self.perform_get_request(&format!("/v1/wg/tunnel/{name}"))
            .await
    }

    pub async fn wg_tunnel_create(&self, req: WgTunnelCreate) -> Result<(), ClientError> {
        self.perform_post_request("/v1/wg/tunnel", req).await
    }

    pub async fn wg_tunnel_delete(&self, name: &str) -> Result<(), ClientError> {
        self.perform_delete_request(&format!("/v1/wg/tunnel/{name}"))
            .await
    }

    pub async fn wg_peer_list(
        &self,
        tunnel: &str,
    ) -> Result<Vec<WgPeerResponse>, ClientError> {
        self.perform_get_request(&format!("/v1/wg/tunnel/{tunnel}/peer"))
            .await
    }

    pub async fn wg_peer_delete(
        &self,
        tunnel: &str,
        peer_uuid: &str,
    ) -> Result<(), ClientError> {
        self.perform_delete_request(&format!("/v1/wg/tunnel/{tunnel}/peer/{peer_uuid}"))
            .await
    }

    pub async fn wg_token_list(
        &self,
        tunnel: &str,
    ) -> Result<Vec<WgTokenInfo>, ClientError> {
        self.perform_get_request(&format!("/v1/wg/tunnel/{tunnel}/token"))
            .await
    }

    pub async fn wg_token_create(
        &self,
        tunnel: &str,
        req: WgTokenCreate,
    ) -> Result<WgTokenCreatedResponse, ClientError> {
        self.perform_post_request(&format!("/v1/wg/tunnel/{tunnel}/token"), req)
            .await
    }

    pub async fn wg_token_delete(
        &self,
        tunnel: &str,
        token: &str,
    ) -> Result<(), ClientError> {
        self.perform_delete_request(&format!("/v1/wg/tunnel/{tunnel}/token/{token}"))
            .await
    }

    pub async fn wg_connect(&self, req: WgConnectRequest) -> Result<WgConnectResponse, ClientError> {
        self.perform_post_request("/v1/wg/connect", req).await
    }
}
