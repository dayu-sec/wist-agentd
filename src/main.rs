#[tokio::main(flavor = "current_thread")]
async fn main() {
    if let Err(err) = wist_agentd::run().await {
        eprintln!("wist-agentd failed: {err}");
        std::process::exit(1);
    }
}
