//! ADR-024 peer-auth pen-test helper (windows-deployment phase 4). Two modes:
//!
//!   pipe_probe server <pipe-name> <token-path>   bind the daemon transport and accept.
//!   pipe_probe probe  <pipe-name>                try to open the pipe; report the result.
//!
//! The pen-test script (`ci/windows-pentest.ps1`) starts a `server` as the runner user and
//! then runs `probe` as a *different* local user: the §5 DACL must refuse that open, so the
//! probe exits non-zero. An open that *succeeds* from a different user is a default-allow
//! security failure and fails the job. The helper is platform-neutral (it uses only the
//! crate's public API); the pen test itself runs only on the Windows lane.

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("server") => {
            let pipe = args.get(2).expect("usage: server <pipe> <token>");
            let token = args.get(3).expect("usage: server <pipe> <token>");
            let listener = faradayd_ipc::Listener::bind(pipe, token).expect("bind");
            // Accept forever so the pipe stays available for the probes.
            loop {
                let _ = listener.accept().await;
            }
        }
        Some("probe") => {
            let pipe = args.get(2).expect("usage: probe <pipe>");
            match faradayd_ipc::connect(pipe).await {
                Ok(_) => {
                    println!("OPENED");
                    std::process::exit(0);
                }
                Err(e) => {
                    println!("REFUSED: {e}");
                    std::process::exit(3);
                }
            }
        }
        _ => {
            eprintln!("usage: pipe_probe server <pipe> <token> | probe <pipe>");
            std::process::exit(2);
        }
    }
}
