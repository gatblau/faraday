//! Plan 04 Phase 3 gate (macOS service + installer, ADR-030/ADR-031). Validates the
//! launchd plist template (`plutil -lint`), builds the unsigned `.pkg` (`build-pkg.sh`),
//! and exercises the `install-mcp-config` subcommand end-to-end (merge, no clobber).
//! The merge logic itself is unit-tested in `src/install.rs`; live `launchctl` load is
//! session-sensitive and not gated here (best-effort in the postinstall).
#![cfg(all(feature = "integration", target_os = "macos"))]

use std::path::PathBuf;
use std::process::Command;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn launchd_plist_template_lints() {
    let plist = repo_root().join("packaging/macos/dev.faraday.faradayd.plist");
    let status = Command::new("plutil")
        .arg("-lint")
        .arg(&plist)
        .status()
        .expect("run plutil");
    assert!(status.success(), "plutil -lint failed for {plist:?}");
}

#[test]
fn build_pkg_produces_an_unsigned_package() {
    let out_dir = std::env::temp_dir().join(format!("pysd-pkg-{}", std::process::id()));
    std::fs::create_dir_all(&out_dir).unwrap();
    // Use the test binary as the staged payload — pkgbuild does not care about opt level.
    let bin = env!("CARGO_BIN_EXE_faradayd");
    let script = repo_root().join("packaging/macos/build-pkg.sh");
    let status = Command::new("bash")
        .arg(&script)
        .arg(bin)
        .env("OUT_DIR", &out_dir)
        .env("PYS_VERSION", "0.0.0-test")
        // no PYS_CODESIGN_IDENTITY / PYS_NOTARY_PROFILE → unsigned, no certs required
        .status()
        .expect("run build-pkg.sh");
    assert!(status.success(), "build-pkg.sh failed");
    let pkg = out_dir.join("faradayd-0.0.0-test.pkg");
    assert!(pkg.exists(), "expected built package at {pkg:?}");
    let _ = std::fs::remove_dir_all(&out_dir);
}

/// The `make install`/`make uninstall` developer targets must install the binary into a
/// user-writable location with no `sudo` (ADR-030/ADR-031 dev convenience). Asserted via a
/// `make -n` dry run, which expands the recipe without executing it — so the check is
/// deterministic and mutates nothing (there is no containerisable service: launchd is
/// host-only). Both the binary copy and the downstream consumers (plist `ProgramArguments`,
/// `install-mcp-config`) must carry the user-local path, and no `/usr/local/bin` must remain.
#[test]
fn make_install_is_user_local_and_sudoless() {
    let dry_run = |target: &str| -> String {
        let out = Command::new("make")
            .arg("-n")
            .arg(target)
            .current_dir(repo_root())
            .output()
            .unwrap_or_else(|e| panic!("run make -n {target}: {e}"));
        assert!(
            out.status.success(),
            "make -n {target} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    };

    let install = dry_run("install");
    let uninstall = dry_run("uninstall");
    let combined = format!("{install}\n{uninstall}");

    assert!(
        !combined.contains("sudo"),
        "install/uninstall must not invoke sudo; dry run was:\n{combined}"
    );
    assert!(
        !combined.contains("/usr/local/bin"),
        "install/uninstall must not target /usr/local/bin; dry run was:\n{combined}"
    );
    assert!(
        install.contains(".local/bin/faradayd"),
        "install must place the binary under ~/.local/bin; dry run was:\n{install}"
    );
}

#[test]
fn install_mcp_config_merges_without_clobber() {
    let dir = std::env::temp_dir().join(format!("pysd-cfg-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = dir.join("claude.json");
    // Pre-existing config with an unrelated server.
    std::fs::write(
        &cfg,
        r#"{"mcpServers": {"other": {"command": "keep-me"}}, "ui": {"theme": "dark"}}"#,
    )
    .unwrap();

    let status = Command::new(env!("CARGO_BIN_EXE_faradayd"))
        .arg("install-mcp-config")
        .arg(&cfg)
        .status()
        .expect("run install-mcp-config");
    assert!(status.success(), "install-mcp-config exited non-zero");

    let merged: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&cfg).unwrap()).unwrap();
    assert_eq!(
        merged["mcpServers"]["other"]["command"], "keep-me",
        "existing server preserved"
    );
    assert_eq!(merged["ui"]["theme"], "dark", "unrelated key preserved");
    assert_eq!(
        merged["mcpServers"]["faradayd"]["args"][0], "mcp-stdio",
        "ours added"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The get-started guide must describe the user-local, password-free install — no stale
/// `/usr/local/bin` path and no promise of a Mac-password prompt — so the walkthrough matches
/// the `make install` target (Phase 2 of the no-sudo plan).
#[test]
fn get_started_doc_matches_user_local_install() {
    let doc =
        std::fs::read_to_string(repo_root().join("get-started.md")).expect("read get-started.md");
    assert!(
        !doc.contains("/usr/local/bin/faradayd"),
        "get-started.md must not reference the old /usr/local/bin path"
    );
    assert!(
        !doc.contains("Mac password"),
        "get-started.md must not promise a Mac-password prompt"
    );
    assert!(
        doc.contains(".local/bin/faradayd"),
        "get-started.md should document the user-local install path"
    );
}
