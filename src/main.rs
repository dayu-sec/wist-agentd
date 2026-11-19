#[tokio::main(flavor = "current_thread")]
async fn main() {
    match wist_agentd::run().await {
        // 0 时正常返回（让 Rust 刷新标准输出缓冲）；doctor 等命令用非零退出码表达「有 FAIL」。
        Ok(0) => {}
        Ok(code) => std::process::exit(code),
        Err(err) => {
            // 打印完整因果链（含 io 源错误）：`/etc` 下的权限失败、配置/状态目录不可写这类问题
            // 只看顶层 reason 是看不出原因的。
            let chain = err.display_chain().to_string();
            eprintln!("wist-agentd failed: {chain}");
            // 同一条遗言再压进内核环形缓冲：stderr 走 journald，而磁盘写满时 journald
            // 自己就写不了盘（`Failed to open system journal: No space left...`），那一次
            // 启动失败会完全无痕（issue #47）。kmsg 不占盘，是那个时候唯一还写得进去的地方。
            wist_agentd::kmsg::mirror_fatal("wist-agentd", &chain);
            std::process::exit(1);
        }
    }
}
