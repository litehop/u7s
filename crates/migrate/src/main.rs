use anyhow::{bail, Context};
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
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let Command::Migrate {
        command:
            Migrate::Export {
                dry_run,
                kubeconfig,
                plan,
                allow_unknown_k3s_version,
            },
    } = Cli::parse().command;
    if !dry_run {
        bail!("only `export --dry-run` is implemented; it changes nothing on the source");
    }
    dry_run_export(&kubeconfig, &plan, allow_unknown_k3s_version).await
}

async fn dry_run_export(
    kubeconfig: &str,
    plan_path: &str,
    allow_unknown: bool,
) -> anyhow::Result<()> {
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
    std::fs::write(plan_path, serde_json::to_string_pretty(&plan)?)
        .with_context(|| format!("writing {plan_path}"))?;
    print!("{}", plan::render_report(&plan, &warnings));
    println!("plan written to {plan_path}");
    if !failures.is_empty() {
        bail!(
            "{} resource list(s) failed; the plan is incomplete",
            failures.len()
        );
    }
    Ok(())
}
