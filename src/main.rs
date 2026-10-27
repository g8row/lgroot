//! LGroot — a small native wizard for rooting LG webOS TVs.
//!
//! Threading model: the UI thread never blocks. All network work happens on a
//! single worker thread, which reports progress through a channel that a
//! `slint::Timer` drains on the UI thread. That matters because pairing waits up
//! to a minute for a human with a remote control.

use lgroot::events::{Command, Event};
use lgroot::session::{run_exploit, with_tv};
use lgroot::{payload, scan, ssap};
use slint::{ComponentHandle, ModelRc, Timer, TimerMode, VecModel};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

slint::include_modules!();

fn main() -> Result<(), slint::PlatformError> {
    // rustls needs a process-wide crypto provider when only one is compiled in,
    // but installing it explicitly avoids any ambiguity.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let ui = AppWindow::new()?;

    let (event_tx, event_rx) = mpsc::channel::<Event>();
    let (command_tx, command_rx) = mpsc::channel::<Command>();
    let cancel = Arc::new(AtomicBool::new(false));

    {
        let tx = event_tx.clone();
        let cancel = cancel.clone();
        thread::spawn(move || worker(tx, command_rx, cancel));
    }

    // ip -> display name, so the pairing screen can show which TV it is talking
    // to without the callback having to carry the whole list.
    let names: Arc<Mutex<HashMap<String, String>>> = Arc::new(Mutex::new(HashMap::new()));

    ui.on_scan_requested({
        let command_tx = command_tx.clone();
        let cancel = cancel.clone();
        move || {
            cancel.store(false, Ordering::Relaxed);
            let _ = command_tx.send(Command::Scan);
        }
    });

    ui.on_tv_picked({
        let command_tx = command_tx.clone();
        let cancel = cancel.clone();
        let names = names.clone();
        let weak = ui.as_weak();
        move |ip| {
            let ip = ip.as_str().to_string();
            if ip.is_empty() {
                return;
            }
            cancel.store(false, Ordering::Relaxed);
            let name = names
                .lock()
                .ok()
                .and_then(|n| n.get(&ip).cloned())
                .unwrap_or_default();
            if let Some(ui) = weak.upgrade() {
                begin_run(&ui, &ip, &name);
                let _ = command_tx.send(Command::Run {
                    ip,
                    local_ip: ui.get_local_ip().to_string(),
                    debug: ui.get_debug_payload(),
                });
            }
        }
    });

    ui.on_probe_requested({
        let command_tx = command_tx.clone();
        let cancel = cancel.clone();
        let weak = ui.as_weak();
        move |ip| {
            let ip = ip.as_str().trim().to_string();
            let Some(ui) = weak.upgrade() else { return };
            if ip.parse::<std::net::Ipv4Addr>().is_err() {
                ui.set_result_title("That is not an IP address".into());
                ui.set_result_body(
                    format!("“{ip}” is not an IPv4 address. It should look like 192.168.1.50.")
                        .into(),
                );
                ui.set_result_hint(
                    "You can read it from the TV under Settings → Network → Wired/Wi-Fi connection."
                        .into(),
                );
                ui.set_page(4);
                return;
            }
            cancel.store(false, Ordering::Relaxed);
            begin_run(&ui, &ip, "LG TV");
            let _ = command_tx.send(Command::Run {
                ip,
                local_ip: ui.get_local_ip().to_string(),
                debug: ui.get_debug_payload(),
            });
        }
    });

    ui.on_cancel_requested({
        let cancel = cancel.clone();
        let weak = ui.as_weak();
        move || {
            cancel.store(true, Ordering::Relaxed);
            if let Some(ui) = weak.upgrade() {
                ui.set_page(0);
            }
        }
    });

    ui.on_restart_requested({
        let command_tx = command_tx.clone();
        let cancel = cancel.clone();
        let weak = ui.as_weak();
        move || {
            cancel.store(false, Ordering::Relaxed);
            if let Some(ui) = weak.upgrade() {
                ui.set_page(0);
                ui.set_advanced(false);
            }
            let _ = command_tx.send(Command::Scan);
        }
    });

    ui.on_test_requested({
        let command_tx = command_tx.clone();
        move || {
            let _ = command_tx.send(Command::Test);
        }
    });

    ui.on_reboot_requested({
        let command_tx = command_tx.clone();
        let weak = ui.as_weak();
        move || {
            if let Some(ui) = weak.upgrade() {
                let _ = command_tx.send(Command::Reboot(ui.get_target_ip().to_string()));
            }
        }
    });

    ui.on_launch_hb_requested({
        let command_tx = command_tx.clone();
        let weak = ui.as_weak();
        move || {
            if let Some(ui) = weak.upgrade() {
                let _ = command_tx.send(Command::LaunchHb(ui.get_target_ip().to_string()));
            }
        }
    });

    // ---- UI pump ----------------------------------------------------------
    let pump = {
        let weak = ui.as_weak();
        let names = names.clone();
        let mut tvs: Vec<TvItem> = Vec::new();
        let mut logs: Vec<slint::SharedString> = Vec::new();
        move || {
            let Some(ui) = weak.upgrade() else { return };
            while let Ok(event) = event_rx.try_recv() {
                match event {
                    Event::ScanStarted => {
                        tvs.clear();
                        logs.clear();
                        if let Ok(mut names) = names.lock() {
                            names.clear();
                        }
                        ui.set_tvs(ModelRc::new(VecModel::from(tvs.clone())));
                        ui.set_log_lines(ModelRc::new(VecModel::from(logs.clone())));
                        ui.set_scanning(true);
                        ui.set_scan_progress(0.0);
                        ui.set_scan_text("starting…".into());
                        ui.set_page(0);
                    }
                    Event::ScanProgress { done, total } => {
                        ui.set_scan_progress(done as f32 / total.max(1) as f32);
                        ui.set_scan_text(format!("Scanned {done} of {total} addresses").into());
                    }
                    Event::TvFound(tv) => {
                        if let Ok(mut names) = names.lock() {
                            names.insert(tv.ip.clone(), tv.name.clone());
                        }
                        tvs.push(TvItem {
                            ip: tv.ip.into(),
                            name: tv.name.into(),
                            detail: tv.detail.into(),
                            badge: tv.badge.into(),
                        });
                        ui.set_tvs(ModelRc::new(VecModel::from(tvs.clone())));
                    }
                    Event::ScanFinished => {
                        ui.set_scanning(false);
                        ui.set_scan_progress(1.0);
                        if tvs.is_empty() {
                            ui.set_scan_text("Nothing answered".into());
                        } else {
                            ui.set_scan_text(
                                format!(
                                    "{} TV{} found",
                                    tvs.len(),
                                    if tvs.len() == 1 { "" } else { "s" }
                                )
                                .into(),
                            );
                        }
                    }
                    Event::Step(step) => {
                        if ui.get_page() == 0 {
                            continue;
                        }
                        ui.set_step(step as i32);
                        if step >= 2 {
                            ui.set_page(2);
                        }
                    }
                    Event::PairCountdown { left, total } => {
                        if ui.get_page() != 1 {
                            continue;
                        }
                        ui.set_pair_countdown(left.to_string().into());
                        ui.set_pair_progress(left as f32 / total.max(1) as f32);
                    }
                    Event::Files { served, total } => {
                        ui.set_files_text(
                            format!("{served} of {total} installer files sent to the TV").into(),
                        );
                    }
                    Event::TestUrl(text) => {
                        ui.set_test_url(text.into());
                    }
                    Event::Log(line) => {
                        eprintln!("[lgroot] {line}");
                        logs.push(line.into());
                        if logs.len() > 400 {
                            logs.remove(0);
                        }
                        ui.set_log_lines(ModelRc::new(VecModel::from(logs.clone())));
                    }
                    Event::Done => {
                        if ui.get_page() == 0 {
                            continue;
                        }
                        ui.set_step(4);
                        ui.set_page(3);
                    }
                    Event::Failed { title, body, hint } => {
                        if ui.get_page() == 0 {
                            continue;
                        }
                        ui.set_result_title(title.into());
                        ui.set_result_body(body.into());
                        ui.set_result_hint(hint.into());
                        ui.set_page(4);
                    }
                }
            }
        }
    };

    let timer = Timer::default();
    timer.start(TimerMode::Repeated, Duration::from_millis(80), pump);

    let _ = command_tx.send(Command::Scan);
    ui.run()
}

/// Reset the per-run state and show the pairing screen.
fn begin_run(ui: &AppWindow, ip: &str, name: &str) {
    ui.set_target_ip(ip.into());
    ui.set_target_name(name.into());
    ui.set_step(0);
    ui.set_files_text("".into());
    ui.set_pair_countdown("60".into());
    ui.set_pair_progress(1.0);
    ui.set_log_lines(ModelRc::new(VecModel::from(Vec::<slint::SharedString>::new())));
    ui.set_page(1);
}

// ---------------------------------------------------------------------------
// Worker
// ---------------------------------------------------------------------------

fn worker(tx: Sender<Event>, rx: Receiver<Command>, cancel: Arc<AtomicBool>) {
    let mut test_server: Option<payload::Server> = None;

    while let Ok(command) = rx.recv() {
        match command {
            Command::Scan => {
                test_server = None;
                scan::run(&tx, &cancel);
            }
            Command::Test => {
                test_server = None;
                match payload::start_test(tx.clone()) {
                    Ok(server) => {
                        let local = scan::default_local_ip().unwrap_or_else(|| "<this computer>".into());
                        let url = format!("http://{local}:{}/", server.port);
                        let _ = tx.send(Event::Log(format!("test server listening on {url}")));
                        let _ = tx.send(Event::TestUrl(
                            format!("Open {url} in the TV's web browser — it should say “Here's your slop, bro!”"),
                        ));
                        test_server = Some(server);
                    }
                    Err(e) => {
                        let _ = tx.send(Event::Log(format!("test server: {e}")));
                    }
                }
            }
            Command::Run {
                ip,
                local_ip,
                debug,
            } => {
                test_server = None;
                if let Err(failure) = run_exploit(&tx, &cancel, &ip, &local_ip, debug) {
                    if !cancel.load(Ordering::Relaxed) {
                        let _ = tx.send(Event::Failed {
                            title: failure.title,
                            body: failure.body,
                            hint: failure.hint,
                        });
                    }
                }
            }
            Command::Reboot(ip) => with_tv(&tx, &ip, |tv| {
                match tv.reboot() {
                    Ok(()) => {
                        let _ = tx.send(Event::Log("asked the TV to restart".into()));
                    }
                    Err(e) => {
                        let _ = tx.send(Event::Failed {
                            title: "Could not restart the TV".into(),
                            body: e,
                            hint: "Use the prompt on the TV screen, or Settings → General → System → Restart."
                                .into(),
                        });
                    }
                }
            }),
            Command::LaunchHb(ip) => with_tv(&tx, &ip, |tv| match tv.launch_app(ssap::HB_CHANNEL) {
                Ok(()) => {
                    let _ = tx.send(Event::Log("opened Homebrew Channel".into()));
                }
                Err(e) => {
                    let _ = tx.send(Event::Failed {
                        title: "Could not open Homebrew Channel".into(),
                        body: e,
                        hint: "Restart the TV and look for Homebrew Channel in the app list.".into(),
                    });
                }
            }),
        }
        let _ = test_server.as_ref();
    }
}
