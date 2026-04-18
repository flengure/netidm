use crate::{handle_client_error, NetidmClientParser, OpType, OutputMode, SkipAuthOpt};

impl SkipAuthOpt {
    pub async fn exec(&self, opt: NetidmClientParser) {
        match self {
            SkipAuthOpt::Show => {
                let client = opt.to_client(OpType::Read).await;
                match client.system_skip_auth_routes_get().await {
                    Ok(list) => match opt.output_mode {
                        OutputMode::Json => {
                            let json = serde_json::to_string(&list)
                                .expect("Failed to serialise list to JSON!");
                            println!("{json}");
                        }
                        OutputMode::Text => {
                            for rule in list {
                                println!("{rule}");
                            }
                            eprintln!("--");
                            eprintln!("Success");
                        }
                    },
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            SkipAuthOpt::Add { rules } => {
                let client = opt.to_client(OpType::Write).await;
                match client.system_skip_auth_routes_append(rules.clone()).await {
                    Ok(_) => opt.output_mode.print_message("Success"),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            SkipAuthOpt::Remove { rules } => {
                let client = opt.to_client(OpType::Write).await;
                match client.system_skip_auth_routes_remove(rules.clone()).await {
                    Ok(_) => opt.output_mode.print_message("Success"),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
        }
    }
}
