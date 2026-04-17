use anyhow::{Context, Result};
use tracing::debug;

/// Run a list of shell hook commands sequentially.
/// Each command is passed to `/bin/sh -c`.
pub async fn run_hooks(hooks: &[String], label: &str) -> Result<()> {
    for cmd in hooks {
        debug!(%label, %cmd, "running hook");
        let cmd_owned = cmd.clone();
        let label_owned = label.to_string();
        tokio::task::spawn_blocking(move || {
            let status = std::process::Command::new("/bin/sh")
                .arg("-c")
                .arg(&cmd_owned)
                .status()
                .with_context(|| format!("failed to spawn hook: {cmd_owned}"))?;
            if !status.success() {
                anyhow::bail!(
                    "{label_owned} hook failed (exit {:?}): {cmd_owned}",
                    status.code()
                );
            }
            Ok::<(), anyhow::Error>(())
        })
        .await
        .with_context(|| format!("hook task panicked: {cmd}"))??;
    }
    Ok(())
}
