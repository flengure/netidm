use crate::{ClientError, NetidmClient};
use netidm_proto::v1::{LogoutDeliveryDto, LogoutDeliveryFilter, LogoutDeliveryListResponse};

impl NetidmClient {
    /// List every back-channel `LogoutDelivery` record, optionally
    /// filtered by status. Admin-only; ACP-gated server-side via
    /// `idm_acp_logout_delivery_read` added in DL26.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] if the request fails at the HTTP layer
    /// or the caller lacks admin privileges.
    pub async fn idm_list_logout_deliveries(
        &self,
        filter: Option<LogoutDeliveryFilter>,
    ) -> Result<Vec<LogoutDeliveryDto>, ClientError> {
        let path = match filter {
            Some(f) => format!("/v1/logout_deliveries?status={}", f.as_str()),
            None => "/v1/logout_deliveries".to_string(),
        };
        let resp: LogoutDeliveryListResponse = self.perform_get_request(path.as_str()).await?;
        Ok(resp.items)
    }

    /// Show one `LogoutDelivery` record by UUID. Returns `Ok(None)` if
    /// the UUID does not exist. Admin-only.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] if the request fails at the HTTP layer
    /// or the caller lacks admin privileges.
    pub async fn idm_show_logout_delivery(
        &self,
        delivery_uuid: uuid::Uuid,
    ) -> Result<Option<LogoutDeliveryDto>, ClientError> {
        let path = format!("/v1/logout_deliveries/{delivery_uuid}");
        match self
            .perform_get_request::<LogoutDeliveryDto>(path.as_str())
            .await
        {
            Ok(d) => Ok(Some(d)),
            Err(ClientError::Http(reqwest::StatusCode::NOT_FOUND, _, _)) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

impl NetidmClient {
    pub async fn system_password_badlist_get(&self) -> Result<Vec<String>, ClientError> {
        let list: Option<Vec<String>> = self
            .perform_get_request("/v1/system/_attr/badlist_password")
            .await?;
        Ok(list.unwrap_or_default())
    }

    pub async fn system_password_badlist_append(
        &self,
        list: Vec<String>,
    ) -> Result<(), ClientError> {
        self.perform_post_request("/v1/system/_attr/badlist_password", list)
            .await
    }

    pub async fn system_password_badlist_remove(
        &self,
        list: Vec<String>,
    ) -> Result<(), ClientError> {
        self.perform_delete_request_with_body("/v1/system/_attr/badlist_password", list)
            .await
    }

    pub async fn system_denied_names_get(&self) -> Result<Vec<String>, ClientError> {
        let list: Option<Vec<String>> = self
            .perform_get_request("/v1/system/_attr/denied_name")
            .await?;
        Ok(list.unwrap_or_default())
    }

    pub async fn system_denied_names_append(&self, list: &Vec<String>) -> Result<(), ClientError> {
        self.perform_post_request("/v1/system/_attr/denied_name", list)
            .await
    }

    pub async fn system_denied_names_remove(&self, list: &Vec<String>) -> Result<(), ClientError> {
        self.perform_delete_request_with_body("/v1/system/_attr/denied_name", list)
            .await
    }

    pub async fn system_skip_auth_routes_get(&self) -> Result<Vec<String>, ClientError> {
        let list: Option<Vec<String>> = self
            .perform_get_request("/v1/system/_attr/skip_auth_route")
            .await?;
        Ok(list.unwrap_or_default())
    }

    pub async fn system_skip_auth_routes_append(
        &self,
        list: Vec<String>,
    ) -> Result<(), ClientError> {
        self.perform_post_request("/v1/system/_attr/skip_auth_route", list)
            .await
    }

    pub async fn system_skip_auth_routes_remove(
        &self,
        list: Vec<String>,
    ) -> Result<(), ClientError> {
        self.perform_delete_request_with_body("/v1/system/_attr/skip_auth_route", list)
            .await
    }
}
