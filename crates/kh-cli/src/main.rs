//! `kh` — the agent-side companion of KeyHolder.
//!
//!   kh mcp                          MCP server over stdio (token in KH_TOKEN)
//!   kh run --ticket T -- <cmd>...   run a command with env-mode keys from a prepare_run ticket
//!   kh scan <path>...               look for stored secret values in files (token in KH_TOKEN)
//!   kh status                       is KeyHolder running / unlocked

mod conn;
mod mcp;

use std::process::ExitCode;

fn usage() -> ExitCode {
    eprintln!(
        "kh {} — KeyHolder CLI\n\n\
         kh mcp                          MCP server for the agent (client token in KH_TOKEN)\n\
         kh run --ticket T -- <command>  run a command with the keys from a prepare_run ticket\n\
         kh scan <path>...               find key values in files (token in KH_TOKEN)\n\
         kh status                       MCP Keyholder status",
        env!("CARGO_PKG_VERSION")
    );
    ExitCode::from(2)
}

/// Windows consoles interpret bytes with the OEM code page; UTF-8 keeps non-ASCII text (key names, paths) readable.
#[cfg(windows)]
fn utf8_console() {
    use windows_sys::Win32::System::Console::{SetConsoleCP, SetConsoleOutputCP};
    unsafe {
        SetConsoleOutputCP(65001);
        SetConsoleCP(65001);
    }
}

#[cfg(not(windows))]
fn utf8_console() {}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> ExitCode {
    utf8_console();
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("mcp") => mcp::run().await,
        Some("run") => run_cmd(&args[1..]).await,
        Some("scan") => scan(&args[1..]).await,
        Some("status") => status().await,
        _ => usage(),
    }
}

async fn status() -> ExitCode {
    match conn::Conn::connect("status", None, false).await {
        Ok(c) => match c.call(kh_core::protocol::methods::STATUS, serde_json::json!({})).await {
            Ok(v) => {
                println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("kh: {e}");
                ExitCode::FAILURE
            }
        },
        Err(e) => {
            eprintln!("kh: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn run_cmd(args: &[String]) -> ExitCode {
    let mut ticket = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--ticket" => {
                ticket = args.get(i + 1).cloned();
                i += 2;
            }
            "--" => {
                i += 1;
                break;
            }
            _ => break,
        }
    }
    let cmd = &args[i..];
    let (Some(ticket), Some(program)) = (ticket, cmd.first()) else {
        eprintln!("usage: kh run --ticket <ticket> -- <command> [args]");
        return ExitCode::from(2);
    };
    let conn = match conn::Conn::connect("run", None, true).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("kh: {e}");
            return ExitCode::FAILURE;
        }
    };
    let env = match conn.call(kh_core::protocol::methods::REDEEM_TICKET, serde_json::json!({ "ticket": ticket })).await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("kh: {e}");
            return ExitCode::FAILURE;
        }
    };
    let vars: Vec<(String, String)> = env
        .get("env")
        .and_then(|e| e.as_object())
        .map(|o| o.iter().map(|(k, v)| (k.clone(), v.as_str().unwrap_or_default().to_string())).collect())
        .unwrap_or_default();
    drop(conn);

    let spawn = |prog: &str, rest: &[String]| {
        std::process::Command::new(prog).args(rest).envs(vars.iter().map(|(k, v)| (k, v))).status()
    };
    let status = match spawn(program, &cmd[1..]) {
        Err(e) if cfg!(windows) && e.kind() == std::io::ErrorKind::NotFound => {
            // .cmd/.bat shims (npm, wrangler, ...) need the shell on Windows.
            let mut all = vec!["/d".to_string(), "/c".to_string()];
            all.extend(cmd.iter().cloned());
            spawn("cmd.exe", &all)
        }
        r => r,
    };
    match status {
        Ok(s) => ExitCode::from(s.code().unwrap_or(1).clamp(0, 255) as u8),
        Err(e) => {
            eprintln!("kh: could not start \"{program}\": {e}");
            ExitCode::FAILURE
        }
    }
}

fn collect_files(path: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    if path.is_dir() {
        if let Ok(rd) = std::fs::read_dir(path) {
            for e in rd.flatten() {
                collect_files(&e.path(), out);
            }
        }
    } else if path.is_file() {
        out.push(path.to_path_buf());
    }
}

async fn scan(paths: &[String]) -> ExitCode {
    if paths.is_empty() {
        eprintln!("usage: kh scan <file or folder>...");
        return ExitCode::from(2);
    }
    let token = std::env::var("KH_TOKEN").ok();
    let conn = match conn::Conn::connect("scan", token, true).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("kh: {e}");
            return ExitCode::FAILURE;
        }
    };
    let mut files = Vec::new();
    for p in paths {
        collect_files(std::path::Path::new(p), &mut files);
    }
    const CHUNK: usize = 900 * 1024;
    const OVERLAP: usize = 64 * 1024;
    let mut total = 0;
    for f in files {
        let Ok(meta) = std::fs::metadata(&f) else { continue };
        if meta.len() > 50 * 1024 * 1024 {
            continue;
        }
        let Ok(bytes) = std::fs::read(&f) else { continue };
        let text = String::from_utf8_lossy(&bytes);
        let mut found = std::collections::BTreeSet::new();
        let mut start = 0;
        while start < text.len() {
            let mut end = (start + CHUNK).min(text.len());
            while !text.is_char_boundary(end) {
                end -= 1;
            }
            match conn.call(kh_core::protocol::methods::CHECK_LEAK, serde_json::json!({ "text": &text[start..end] })).await {
                Ok(v) => {
                    for n in v.get("found").and_then(|x| x.as_array()).into_iter().flatten() {
                        if let Some(s) = n.as_str() {
                            found.insert(s.to_string());
                        }
                    }
                }
                Err(e) => {
                    eprintln!("kh: {}: {e}", f.display());
                    return ExitCode::FAILURE;
                }
            }
            if end == text.len() {
                break;
            }
            let mut next = end.saturating_sub(OVERLAP).max(start + 1);
            while !text.is_char_boundary(next) {
                next += 1;
            }
            start = next;
        }
        if !found.is_empty() {
            total += found.len();
            println!("{}: {}", f.display(), found.into_iter().collect::<Vec<_>>().join(", "));
        }
    }
    if total == 0 {
        println!("No key values found.");
        ExitCode::SUCCESS
    } else {
        println!("The keys found are now marked as leaked in MCP Keyholder.");
        ExitCode::from(1)
    }
}
