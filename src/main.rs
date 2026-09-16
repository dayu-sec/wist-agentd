#[tokio::main(flavor = "current_thread")]
async fn main() {
    if let Err(err) = wist_agentd::run().await {
        // 打印完整因果链（含 io 源错误）：`/etc` 下的权限失败、配置/状态目录不可写这类问题
        // 只看顶层 reason 是看不出原因的。
        eprintln!("wist-agentd failed: {}", err.display_chain());
        std::process::exit(1);
    }
}
