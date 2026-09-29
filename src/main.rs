#[tokio::main(flavor = "current_thread")]
async fn main() {
    match wist_agentd::run().await {
        // 0 时正常返回（让 Rust 刷新标准输出缓冲）；doctor 等命令用非零退出码表达「有 FAIL」。
        Ok(0) => {}
        Ok(code) => std::process::exit(code),
        Err(err) => {
            // 打印完整因果链（含 io 源错误）：`/etc` 下的权限失败、配置/状态目录不可写这类问题
            // 只看顶层 reason 是看不出原因的。
            eprintln!("wist-agentd failed: {}", err.display_chain());
            std::process::exit(1);
        }
    }
}
