//! CLI handler for the top-level `netidm logout-deliveries` subcommand
//! tree. Admin-only inspection of the back-channel logout delivery
//! queue. See `specs/009-rp-logout/contracts/cli-commands.md` §5.

use netidm_client::{ClientError, StatusCode};
use netidm_proto::v1::{LogoutDeliveryDto, LogoutDeliveryFilter};

use crate::common::OpType;
use crate::{handle_client_error, LogoutDeliveriesOpt, NetidmClientParser};

impl LogoutDeliveriesOpt {
    pub async fn exec(&self, opt: NetidmClientParser) {
        match self {
            LogoutDeliveriesOpt::List {
                pending,
                succeeded,
                failed,
            } => {
                // Count of status flags set — more than one is a user
                // error; no flags means "all statuses".
                let set_flags = [*pending, *succeeded, *failed]
                    .iter()
                    .filter(|b| **b)
                    .count();
                if set_flags > 1 {
                    opt.output_mode.print_message(
                        "Specify at most one of --pending, --succeeded, --failed.",
                    );
                    return;
                }
                let filter = if *pending {
                    Some(LogoutDeliveryFilter::Pending)
                } else if *succeeded {
                    Some(LogoutDeliveryFilter::Succeeded)
                } else if *failed {
                    Some(LogoutDeliveryFilter::Failed)
                } else {
                    None
                };
                let client = opt.to_client(OpType::Read).await;
                match client.idm_list_logout_deliveries(filter).await {
                    Ok(items) => {
                        if items.is_empty() {
                            opt.output_mode.print_message("(no delivery records)");
                        } else {
                            for item in items {
                                opt.output_mode.print_message(format_row(&item));
                            }
                        }
                    }
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            LogoutDeliveriesOpt::Show { uuid } => {
                let parsed = match uuid::Uuid::parse_str(uuid) {
                    Ok(u) => u,
                    Err(_) => {
                        opt.output_mode
                            .print_message(format!("'{uuid}' is not a valid UUID."));
                        return;
                    }
                };
                let client = opt.to_client(OpType::Read).await;
                match client.idm_show_logout_delivery(parsed).await {
                    Ok(Some(item)) => {
                        opt.output_mode.print_message(format_detail(&item));
                    }
                    Ok(None) => {
                        opt.output_mode
                            .print_message(format!("No delivery record with UUID {uuid}."));
                    }
                    Err(ClientError::Http(StatusCode::NOT_FOUND, _, _)) => {
                        opt.output_mode
                            .print_message(format!("No delivery record with UUID {uuid}."));
                    }
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
        }
    }
}

fn format_row(item: &LogoutDeliveryDto) -> String {
    format!(
        "{uuid}\t{status}\trp:{rp}\tattempts:{attempts}\tnext:{next}\tcreated:{created}\t{endpoint}",
        uuid = item.uuid,
        status = item.status,
        rp = item.rp,
        attempts = item.attempts,
        next = item.next_attempt,
        created = item.created,
        endpoint = item.endpoint
    )
}

fn format_detail(item: &LogoutDeliveryDto) -> String {
    format!(
        "UUID:         {uuid}\n\
         RP:           {rp}\n\
         Endpoint:     {endpoint}\n\
         Status:       {status}\n\
         Attempts:     {attempts}\n\
         Next attempt: {next}\n\
         Created:      {created}",
        uuid = item.uuid,
        rp = item.rp,
        endpoint = item.endpoint,
        status = item.status,
        attempts = item.attempts,
        next = item.next_attempt,
        created = item.created
    )
}
