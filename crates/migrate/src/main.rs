use anyhow::bail;
use clap::{Parser, Subcommand};
use serde_json::Value;
use u7s_apiserver::migrate_tables::{shipped_addons, strippable_finalizers};
use u7s_migrate::{discover, plan};

#[derive(Parser)]
#[command(name = "u7s", about = "u7s command line", version = u7s_version::version_string())]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Move a single-node k3s cluster onto u7s.
    Migrate {
        #[command(subcommand)]
        command: Migrate,
    },
}

#[derive(Subcommand)]
enum Migrate {
    /// Read the source cluster and classify what would migrate.
    Export {
        /// Report and write the plan without exporting anything.
        #[arg(long)]
        dry_run: bool,
        /// Source cluster kubeconfig (client-certificate auth).
        #[arg(long, default_value = "/etc/rancher/k3s/k3s.yaml")]
        kubeconfig: String,
        /// Where to write the editable plan.
        #[arg(long, default_value = "u7s-migrate-plan.json")]
        plan: String,
        /// Classify a k3s version without a shipped-manifest table with the
        /// nearest lower supported one.
        #[arg(long)]
        allow_unknown_k3s_version: bool,
        /// Where a real export writes the source objects. Created with mode
        /// 0600 and refused if the path exists (the plan is then left
        /// untouched); it contains Secrets in clear text, delete it after the
        /// migration.
        #[arg(long, default_value = "u7s-migrate-objects.json")]
        objects: String,
    },
    /// Recreate the plan's included objects on a u7s apiserver. Re-runnable.
    ///
    /// Every created object gets the permanent annotation
    /// `migrate.u7s.dev/source-uid` (its UID on the source). Do not remove
    /// it: a re-run adopts only same-named objects carrying it and reports
    /// any other as a failure, leaving it untouched. Admission
    /// configurations are created last, each only after its webhook's
    /// Service answers over TLS (probed through the target apiserver's
    /// service proxy, up to 90s); on timeout the configurations are not
    /// created and the run fails naming the webhook. Re-run once the
    /// workload is up.
    Import {
        /// Target u7s kubeconfig (client-certificate auth).
        #[arg(long)]
        kubeconfig: String,
        /// The (possibly edited) plan written by `export`.
        #[arg(long, default_value = "u7s-migrate-plan.json")]
        plan: String,
        /// The objects file written by `export`.
        #[arg(long, default_value = "u7s-migrate-objects.json")]
        objects: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let Command::Migrate { command } = Cli::parse().command;
    match command {
        Migrate::Export {
            dry_run,
            kubeconfig,
            plan,
            allow_unknown_k3s_version,
            objects,
        } => {
            export(
                &kubeconfig,
                &plan,
                allow_unknown_k3s_version,
                (!dry_run).then_some(objects.as_str()),
            )
            .await
        }
        Migrate::Import {
            kubeconfig,
            plan,
            objects,
        } => import(&kubeconfig, &plan, &objects).await,
    }
}

async fn import(kubeconfig: &str, plan: &str, objects: &str) -> anyhow::Result<()> {
    let (plan, objs) = u7s_migrate::import::load(plan, objects)?;
    let mut target = u7s_migrate::import::Live::connect(kubeconfig).await?;
    let report = u7s_migrate::import::run(&mut target, &plan, &objs).await?;
    print!("{}", report.render());
    if !report.failures.is_empty() {
        bail!("{} step(s) failed; re-run to resume", report.failures.len());
    }
    Ok(())
}

/// With `objects` set, also writes the source objects for `import`.
async fn export(
    kubeconfig: &str,
    plan_path: &str,
    allow_unknown: bool,
    objects: Option<&str>,
) -> anyhow::Result<()> {
    if let Some(path) = objects {
        u7s_migrate::refuse_existing(path)?;
    }
    let src = discover::Source::connect(kubeconfig)?;
    let (types, mut failures) = src.resource_types().await?;
    let listing = src.list_all(&types).await;
    failures.extend(listing.failures);
    let objs = listing.objects;

    let nodes: Vec<Value> = objs
        .iter()
        .filter(|o| o["kind"] == "Node" && o["apiVersion"] == "v1")
        .cloned()
        .collect();
    let tag = discover::k3s_version(&nodes)?;
    let shipped = shipped_addons(&tag, allow_unknown)?;

    let source = plan::Source {
        k3s_version: tag.clone(),
        shipped_table: shipped.table_tag.to_string(),
        service_cidrs: discover::service_cidrs(&objs),
        pod_cidrs: discover::pod_cidrs(&nodes),
        kube_dns_cluster_ip: discover::kube_dns_cluster_ip(&objs),
    };
    let (plan, mut warnings) =
        plan::build(&objs, source, shipped.addons, strippable_finalizers(&tag));
    if shipped.approximate {
        warnings.push(format!(
            "k3s {tag} has no exact shipped-manifest table; classified with {}",
            shipped.table_tag
        ));
    }
    if strippable_finalizers(&tag).is_empty() {
        warnings.push(format!(
            "k3s {tag} is outside the audited finalizer range: no finalizer will be stripped"
        ));
    }
    for f in &failures {
        warnings.push(format!("list failed, plan is incomplete: {f}"));
    }

    plan.validate().map_err(anyhow::Error::msg)?;
    let plan_json = serde_json::to_string_pretty(&plan)?;
    let objects_json = serde_json::to_string(&objs)?;
    let objects = objects.filter(|_| failures.is_empty());
    u7s_migrate::write_export(
        plan_path,
        &plan_json,
        objects.map(|p| (p, objects_json.as_bytes())),
    )?;
    print!("{}", plan::render_report(&plan, &warnings));
    println!("plan written to {plan_path}");
    if !failures.is_empty() {
        bail!(
            "{} resource list(s) failed; the plan is incomplete",
            failures.len()
        );
    }
    if let Some(path) = objects {
        println!("objects written to {path}");
        println!(
            "WARNING: {path} contains every exported object including Secrets in clear text \
             (mode 0600). Keep it private and delete it after the migration is complete."
        );
    }
    Ok(())
}
