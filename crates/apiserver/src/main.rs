use clap::Parser;
use u7s_apiserver::{run, Args};

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    run(args).await
}
