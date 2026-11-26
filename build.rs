//! 构建期把 tc 流记录程序编成 BPF 对象（Linux only）。
//!
//! 不做外部依赖：只要能找到 `clang` 就用它编；找不到就**不设 `have_flow_bpf`**，
//! 采集层如实报 `unsupported`（`NotBuilt`）。这样 macOS / 没装 clang 的构建机仍然能出包，
//! 而不是让整个 crate 编不过。

use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=src/telemetry/flows/bpf/flow.bpf.c");
    println!("cargo:rerun-if-changed=src/telemetry/flows/bpf/bpf_min.h");
    println!("cargo:rustc-check-cfg=cfg(have_flow_bpf)");

    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os != "linux" {
        return;
    }

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
    let obj = out_dir.join("flow.bpf.o");
    // `-g` 让 clang 产出 BTF：BTF 风格的 map 定义（`__uint/__type`）需要它。
    let clang = std::env::var("CLANG").unwrap_or_else(|_| "clang".to_string());
    // `linux/bpf.h` 会经 `linux/types.h` 找 `asm/types.h`：它在多架构头目录里，
    // 不在 `/usr/include` 下。BPF 对象本身与目标架构无关（bpfel），这里用**构建机**架构即可。
    let asm_include = format!("-I/usr/include/{}-linux-gnu", std::env::consts::ARCH);
    let result = Command::new(&clang)
        .args([
            "-O2",
            "-g",
            "-Wall",
            "-target",
            "bpfel",
            "-mcpu=v2",
            asm_include.as_str(),
            "-c",
            "src/telemetry/flows/bpf/flow.bpf.c",
            "-o",
            obj.to_str().expect("bpf obj path"),
        ])
        .output();

    match result {
        Ok(output) if output.status.success() => println!("cargo:rustc-cfg=have_flow_bpf"),
        Ok(output) => {
            // clang 在、但编不过 = **构建坏了**：静默降级会让制品看起来正常却没有采集器。
            let stderr = String::from_utf8_lossy(&output.stderr);
            panic!("flow.bpf.c 编译失败（{}）：\n{}", output.status, stderr);
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            println!("cargo:warning=找不到 clang：流记录采集将报 unsupported（设置 CLANG 可指定）")
        }
        Err(err) => panic!("无法执行 clang（{}）：{err}", clang),
    }
}
