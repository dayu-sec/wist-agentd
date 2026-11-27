//! 构建期把 tc 流记录程序编成 BPF 对象（Linux only）。
//!
//! 默认行为：能找到 `clang` 就用它编；找不到就**不设 `have_flow_bpf`**，采集层如实报
//! `unsupported`（`NotBuilt`）。这样 macOS / 没装 clang 的开发机构建仍然能出包。
//!
//! 例外：`WIST_REQUIRE_FLOW_BPF=1`（CI / 发布机构建）时，clang 缺失 = **构建失败**。
//! 那个开关只允许存在一个方向：宁可红，也不要出一个“没有采集器”的制品 —— 它在全机队
//! 表现为“授权了、没数据”，比构建失败难查得多。

use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=src/telemetry/flows/bpf/flow.bpf.c");
    println!("cargo:rerun-if-changed=src/telemetry/flows/bpf/bpf_min.h");
    println!("cargo:rerun-if-env-changed=CLANG");
    println!("cargo:rerun-if-env-changed=WIST_REQUIRE_FLOW_BPF");
    println!("cargo:rustc-check-cfg=cfg(have_flow_bpf)");

    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os != "linux" {
        return;
    }
    // CI / 发布机构建**必须**带上采集器：没有 clang 就让构建失败，
    // 而不是出一个“看着正常、全机队报 unsupported”的制品。
    let require = std::env::var("WIST_REQUIRE_FLOW_BPF")
        .map(|value| matches!(value.as_str(), "1" | "true" | "yes"))
        .unwrap_or(false);

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
            if require {
                panic!(
                    "找不到 clang（{clang}）：WIST_REQUIRE_FLOW_BPF=1 要求这个构建带上流记录采集器。\n\
                     装上 clang（Ubuntu：`apt-get install -y clang-18`，可用 CLANG 指定路径）后重试。"
                );
            }
            println!("cargo:warning=找不到 clang：流记录采集将报 unsupported（设置 CLANG 可指定）")
        }
        Err(err) => panic!("无法执行 clang（{}）：{err}", clang),
    }
}
