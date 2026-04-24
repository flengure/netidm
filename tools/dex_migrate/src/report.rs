/// Accumulates migration statistics and failure details for final reporting.
#[derive(Default)]
pub struct MigrationReport {
    would_create: Vec<(String, String)>,
    created: Vec<(String, String)>,
    failed: Vec<(String, String, String)>,
}

impl MigrationReport {
    /// Record an entry that would be created in a dry-run.
    pub fn would_create(&mut self, kind: &str, name: &str) {
        self.would_create.push((kind.to_string(), name.to_string()));
    }

    /// Record a successfully created entry.
    pub fn created(&mut self, kind: &str, name: &str) {
        self.created.push((kind.to_string(), name.to_string()));
    }

    /// Record a failed entry creation.
    pub fn failed(&mut self, kind: &str, name: &str, err: &str) {
        self.failed
            .push((kind.to_string(), name.to_string(), err.to_string()));
    }

    /// Print a human-readable summary to stdout.
    pub fn print(&self) {
        if !self.would_create.is_empty() {
            println!(
                "--- Dry run: would create {} entries ---",
                self.would_create.len()
            );
            for (kind, name) in &self.would_create {
                println!("  [DRY] {kind}: {name}");
            }
        }

        if !self.created.is_empty() {
            println!("--- Created {} entries ---", self.created.len());
            for (kind, name) in &self.created {
                println!("  [OK]  {kind}: {name}");
            }
        }

        if !self.failed.is_empty() {
            println!("--- Failed {} entries ---", self.failed.len());
            for (kind, name, err) in &self.failed {
                println!("  [ERR] {kind}: {name} — {err}");
            }
        }

        let total = self.would_create.len() + self.created.len() + self.failed.len();
        println!(
            "\nSummary: {} total  ({} ok, {} failed, {} dry-run)",
            total,
            self.created.len(),
            self.failed.len(),
            self.would_create.len(),
        );
    }
}
