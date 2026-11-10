//! The Container entrypoint must not print a token it generates. The value is stored in the data
//! directory, and the log names that file instead. It must also stay the server's parent, so the
//! stop signal a container runtime sends reaches the server. Unix only: the entrypoint is POSIX sh.
#![cfg(unix)]

#[path = "support/executable.rs"]
mod executable;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

#[test]
fn a_generated_token_is_stored_and_never_printed() {
    let root = std::env::temp_dir().join(format!("huntsman-entrypoint-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    let data = root.join("data");
    fs::create_dir_all(&data).unwrap();

    // A stub stands in for the binary, so the entrypoint's final exec runs nothing that serves.
    let stub = root.join("huntsman-recon");
    executable::write_executable(&stub, "#!/bin/sh\nexit 0\n", 0o755);

    let output = Command::new("sh")
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/container-entrypoint.sh"))
        .env_remove("HSE_AUTH_TOKEN")
        .env("HUNTSMAN_DATA_DIR", &data)
        .env("HUNTSMAN_BIN", &stub)
        .env("HUNTSMAN_STARTUP_CHECK", "0")
        .env("PORT", "8080")
        .output()
        .unwrap();

    let stored = fs::read_to_string(data.join(".huntsman").join("container-auth-token")).unwrap();
    let token = stored.trim();
    assert_eq!(token.len(), 64, "a 256-bit token, hex encoded");

    // A host logs both streams, so neither may carry the token. The messages leave the output out:
    // on failure it would print the token.
    for (name, stream) in [("stdout", &output.stdout), ("stderr", &output.stderr)] {
        assert!(
            !String::from_utf8_lossy(stream).contains(token),
            "the generated token reached {name}"
        );
    }
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("container-auth-token"),
        "stderr does not name the stored file"
    );
    let _ = fs::remove_dir_all(&root);
}

/// Without an explicit `HSE_BIND`, the entrypoint binds every interface over both address
/// families where the kernel offers IPv6 (a platform's private network can be IPv6-only), else
/// over IPv4 alone; an explicit bind is handed on as given. The choice is logged.
#[test]
fn the_bind_follows_the_kernel_s_address_families_unless_given() {
    let root =
        std::env::temp_dir().join(format!("huntsman-entrypoint-bind-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    let data = root.join("data");
    fs::create_dir_all(&data).unwrap();
    // The stub records the bind the entrypoint handed it.
    let stub = root.join("huntsman-recon");
    executable::write_executable(
        &stub,
        "#!/bin/sh\nprintf '%s' \"$HSE_BIND\" > \"$HUNTSMAN_BIND_SEEN\"\nexit 0\n",
        0o755,
    );
    let seen = root.join("bind");
    let state = root.join("disable_ipv6");
    // Run as root, the entrypoint drops privileges through gosu; a stand-in runs the command as
    // is, so the test sees the bind wherever it runs.
    let tools = root.join("tools");
    fs::create_dir_all(&tools).unwrap();
    executable::write_executable(
        &tools.join("gosu"),
        "#!/bin/sh\nshift\nexec \"$@\"\n",
        0o755,
    );
    let path = format!(
        "{}:{}",
        tools.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let run = |explicit: Option<&str>, ipv6_disabled: Option<&str>| {
        let _ = fs::remove_file(&seen);
        match ipv6_disabled {
            Some(value) => fs::write(&state, format!("{value}\n")).unwrap(),
            None => {
                let _ = fs::remove_file(&state);
            }
        }
        let mut command = Command::new("sh");
        command
            .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/container-entrypoint.sh"))
            .env("HSE_AUTH_TOKEN", "a-token-for-the-test")
            .env("HUNTSMAN_DATA_DIR", &data)
            .env("HUNTSMAN_BIN", &stub)
            .env("HUNTSMAN_BIND_SEEN", &seen)
            .env("HUNTSMAN_IPV6_STATE_FILE", &state)
            .env("HUNTSMAN_STARTUP_CHECK", "0")
            .env("PATH", &path)
            .env("PORT", "8080")
            .env_remove("HSE_BIND");
        if let Some(bind) = explicit {
            command.env("HSE_BIND", bind);
        }
        let output = command.output().unwrap();
        assert!(output.status.success(), "{output:?}");
        let bind = fs::read_to_string(&seen).unwrap();
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(&format!("serving on {bind}")),
            "the bind is logged: {output:?}"
        );
        bind
    };
    assert_eq!(
        run(None, Some("0")),
        "[::]:8080",
        "IPv6 offered: both families"
    );
    assert_eq!(
        run(None, Some("1")),
        "0.0.0.0:8080",
        "IPv6 disabled: IPv4 alone"
    );
    assert_eq!(run(None, None), "0.0.0.0:8080", "no IPv6 stack: IPv4 alone");
    assert_eq!(
        run(Some("127.0.0.1:9000"), Some("0")),
        "127.0.0.1:9000",
        "an explicit bind is handed on as given"
    );
    let _ = fs::remove_dir_all(&root);
}

/// Poll `ready` every 20 ms for up to ten seconds.
fn wait_for(mut ready: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if ready() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    ready()
}

/// In a container the entrypoint is PID 1, and PID 1 ignores every signal it has no handler for.
/// A server exec'd in the entrypoint's place would never see the SIGTERM a stop request or
/// `docker stop` sends, and would be killed when the grace period ends. So the server must run
/// as the entrypoint's child, and the entrypoint must hand it the stop signal and exit with the
/// server's status.
/// The stop signal races the entrypoint starting its server, and the status it exits with can
/// be lost when the shell handles the signal while it waits. One round is quick but rarely
/// loses the race, so each test runs many rounds.
#[test]
fn the_server_runs_under_the_entrypoint_which_hands_it_the_stop_signal() {
    for round in 0..STOP_ROUNDS {
        stop_signal_round(round);
    }
}

const STOP_ROUNDS: u32 = 100;

fn stop_signal_round(round: u32) {
    let root: PathBuf = std::env::temp_dir().join(format!(
        "huntsman-entrypoint-stop-{}-{round}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    let data = root.join("data");
    fs::create_dir_all(&data).unwrap();

    // The stub records its pid and its parent's, then waits for SIGTERM and exits 3 on it.
    let stub = root.join("huntsman-recon");
    executable::write_executable(
        &stub,
        "#!/bin/sh\n\
         trap 'echo stopped > \"$STUB_DIR/stopped\"; exit 3' TERM\n\
         echo \"$$ $PPID\" > \"$STUB_DIR/server.tmp\"\n\
         mv \"$STUB_DIR/server.tmp\" \"$STUB_DIR/server\"\n\
         while :; do sleep 1 & wait $!; done\n",
        0o755,
    );
    // As root the entrypoint drops to the service user through gosu; a stand-in keeps the user.
    let bin = root.join("bin");
    fs::create_dir_all(&bin).unwrap();
    let gosu = bin.join("gosu");
    executable::write_executable(&gosu, "#!/bin/sh\nshift\nexec \"$@\"\n", 0o755);
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    let mut entrypoint = Command::new("sh")
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/container-entrypoint.sh"))
        .env("PATH", path)
        .env("HSE_AUTH_TOKEN", "test-token")
        .env("HUNTSMAN_DATA_DIR", &data)
        .env("HUNTSMAN_BIN", &stub)
        .env("HUNTSMAN_STARTUP_CHECK", "0")
        .env("PORT", "8080")
        .env("STUB_DIR", &root)
        .spawn()
        .unwrap();

    let started = wait_for(|| root.join("server").exists());
    let recorded = fs::read_to_string(root.join("server")).unwrap_or_default();
    let pids: Vec<u32> = recorded
        .split_whitespace()
        .filter_map(|pid| pid.parse().ok())
        .collect();
    let stop = |pid: u32| {
        let _ = Command::new("kill")
            .args(["-TERM", &pid.to_string()])
            .status();
    };
    if !started || pids.len() != 2 || pids[1] != entrypoint.id() {
        stop(entrypoint.id());
        if let Some(&server) = pids.first() {
            stop(server);
        }
        let _ = entrypoint.wait();
        let _ = fs::remove_dir_all(&root);
        panic!(
            "the server must be the entrypoint's child (entrypoint pid {}), recorded {recorded:?}",
            entrypoint.id()
        );
    }

    stop(entrypoint.id());
    let mut status = None;
    let exited = wait_for(|| {
        status = entrypoint.try_wait().unwrap();
        status.is_some()
    });
    if !exited {
        stop(pids[0]);
        let _ = entrypoint.kill();
        let _ = entrypoint.wait();
    }
    let stopped = root.join("stopped").exists();
    let _ = fs::remove_dir_all(&root);
    assert!(exited, "the entrypoint did not exit after SIGTERM");
    assert!(stopped, "the server never received the stop signal");
    assert_eq!(
        status.and_then(|status| status.code()),
        Some(3),
        "the entrypoint exits with the server's status"
    );
}
