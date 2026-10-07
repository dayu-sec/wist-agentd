//! `agent_runtime.json` store.

use std::io;
use std::path::{Path, PathBuf};

use wist_contracts::agent_state::AgentRuntimeState;
use wist_contracts::agent_state::RuntimeMode;
use wist_shared::fs::{read_json, write_json_private_atomic};

use crate::fs_async::{read_json_async, write_json_private_atomic_async};
use wist_shared::paths::AGENT_RUNTIME_FILE;
use wist_shared::time::now_rfc3339;

pub fn load_default() -> AgentRuntimeState {
    AgentRuntimeState::new(
        "local-agent".to_string(),
        default_instance_id(),
        env!("CARGO_PKG_VERSION").to_string(),
        RuntimeMode::Normal,
        now_rfc3339(),
    )
}

pub fn path_for(state_dir: &Path) -> PathBuf {
    state_dir.join(AGENT_RUNTIME_FILE)
}

pub fn load_or_default(path: &Path) -> io::Result<AgentRuntimeState> {
    if path.exists() {
        read_json(path)
    } else {
        Ok(load_default())
    }
}

pub fn store(path: &Path, state: &AgentRuntimeState) -> io::Result<()> {
    write_json_private_atomic(path, state)
}

pub async fn load_or_default_async(path: &Path) -> io::Result<AgentRuntimeState> {
    match tokio::fs::metadata(path).await {
        Ok(_) => read_json_async(path).await,
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(load_default()),
        Err(err) => Err(err),
    }
}

pub async fn store_async(path: &Path, state: &AgentRuntimeState) -> io::Result<()> {
    write_json_private_atomic_async(path, state).await
}

fn default_instance_id() -> String {
    // 机器名优先级只有一份实现：`discovery::host`；这里只决定「都拿不到」时的占位名。
    crate::discovery::host::resolve_host_name().unwrap_or_else(|| "local-instance".to_string())
}

#[cfg(test)]
mod tests {
    use super::{default_instance_id, load_or_default_async, path_for, store, store_async};
    use std::time::{SystemTime, UNIX_EPOCH};
    use wist_contracts::agent_state::{AgentRuntimeState, RuntimeMode};

    #[test]
    fn default_instance_id_is_never_empty() {
        assert!(!default_instance_id().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn store_writes_private_runtime_state_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let state_dir = std::env::temp_dir().join(format!(
            "wist-agentd-agent-runtime-perms-{}",
            unique_suffix()
        ));
        let path = path_for(&state_dir);
        let mut state = AgentRuntimeState::new(
            "agent-a".to_string(),
            "instance-a".to_string(),
            "v0.1.0".to_string(),
            RuntimeMode::Normal,
            "2026-07-29T00:00:00Z".to_string(),
        );
        state.credential_id = Some("cred-secret".to_string());

        store(&path, &state).expect("store runtime state");

        let dir_mode = std::fs::metadata(&state_dir)
            .expect("state dir metadata")
            .permissions()
            .mode()
            & 0o777;
        let file_mode = std::fs::metadata(&path)
            .expect("runtime file metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700);
        assert_eq!(file_mode, 0o600);

        let _ = std::fs::remove_dir_all(state_dir);
    }

    #[tokio::test]
    async fn store_and_load_async_round_trip() {
        let state_dir = std::env::temp_dir().join(format!(
            "wist-agentd-agent-runtime-async-{}",
            unique_suffix()
        ));
        let path = path_for(&state_dir);
        let mut state = AgentRuntimeState::new(
            "agent-a".to_string(),
            "instance-a".to_string(),
            "v0.1.0".to_string(),
            RuntimeMode::Normal,
            "2026-07-29T00:00:00Z".to_string(),
        );
        state.credential_id = Some("cred-secret".to_string());

        store_async(&path, &state).await.expect("store");
        let loaded = load_or_default_async(&path).await.expect("load");

        assert_eq!(loaded, state);
        let _ = tokio::fs::remove_dir_all(&state_dir).await;
    }

    fn unique_suffix() -> u128 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos()
    }
}
