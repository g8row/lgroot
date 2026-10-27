//! The actual rooting flow, independent of any UI.
//!
//! Kept in the library so it can be driven by an integration test against a
//! mock TV as well as by the Slint front-end.

use crate::events::Event;
use crate::{keystore, payload, scan, ssap};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

pub struct Failure {
    pub title: String,
    pub body: String,
    pub hint: String,
}

impl Failure {
    pub fn new(title: &str, body: impl Into<String>, hint: &str) -> Self {
        Failure {
            title: title.to_string(),
            body: body.into(),
            hint: hint.to_string(),
        }
    }
}

/// Reconnect to an already-paired TV and run one small request.
pub fn with_tv(tx: &Sender<Event>, ip: &str, action: impl FnOnce(&mut ssap::Ssap)) {
    let mut tv = match ssap::Ssap::connect(ip, tx) {
        Ok(tv) => tv,
        Err(e) => {
            let _ = tx.send(Event::Log(format!("could not reconnect: {e}")));
            return;
        }
    };
    let stored = keystore::load(ip);
    match tv.register(&stored, Duration::from_secs(15), |_, _| {}, || false) {
        Ok(_) => action(&mut tv),
        Err(e) => {
            let _ = tx.send(Event::Log(format!("could not reconnect: {e}")));
        }
    }
    tv.close();
}

pub fn run_exploit(
    tx: &Sender<Event>,
    cancel: &Arc<AtomicBool>,
    ip: &str,
    local_override: &str,
    debug: bool,
) -> Result<(), Failure> {
    let _ = tx.send(Event::Step(0));
    let _ = tx.send(Event::Log(format!("target {ip}")));

    let local = if local_override.trim().is_empty() {
        scan::local_ip_for(ip).ok_or_else(|| {
            Failure::new(
                "Could not work out this computer's address",
                "The TV needs an address to download the installer from, and the routing table did not give us one.",
                "Open Options and type this computer's LAN address, for example 192.168.1.23.",
            )
        })?
    } else {
        local_override.trim().to_string()
    };
    let _ = tx.send(Event::Log(format!("advertising {local} to the TV")));

    let tracker = payload::Tracker::new();
    let server = payload::start_payload(tx.clone(), tracker.clone()).map_err(|e| {
        Failure::new(
            "Could not start the installer server",
            e,
            "Close whatever is using port 8080 (another copy of this app?) and try again.",
        )
    })?;
    let _ = tx.send(Event::Log(format!(
        "installer server listening on port {}",
        server.port
    )));

    let mut url = format!(
        "http://{local}:{}/index.html?script=autoroot.sh&files={}&fake-service-path=/usr/palm/services/com.palm.service.devmode",
        server.port,
        payload::DOWNLOAD_LIST
    );
    if debug {
        url.push_str("&debug");
    }

    let mut tv = ssap::Ssap::connect(ip, tx).map_err(|e| {
        Failure::new(
            "Could not reach the TV",
            e,
            "Check that the TV is switched on (not in deep standby), on the same Wi-Fi as this computer, and that the router is not isolating clients from each other.",
        )
    })?;
    let _ = tx.send(Event::Step(1));

    let stored = keystore::load(ip);
    if stored.is_empty() {
        let _ = tx.send(Event::Log(
            "no saved key; the TV will ask you to allow this computer".into(),
        ));
    } else {
        let _ = tx.send(Event::Log("using the saved pairing key".into()));
    }

    let tick_tx = tx.clone();
    let key = tv
        .register(
            &stored,
            Duration::from_secs(60),
            move |left, total| {
                let _ = tick_tx.send(Event::PairCountdown { left, total });
            },
            || cancel.load(Ordering::Relaxed),
        )
        .map_err(|e| {
            let lower = e.to_lowercase();
            if lower.contains("cancel") || e.contains("403") {
                Failure::new(
                    "Cancelled on the TV",
                    "The prompt on the TV was declined, so nothing was installed.",
                    "Run it again and choose OK or Yes on the remote.",
                )
            } else if lower.contains("timed out") || lower.contains("timeout") {
                Failure::new(
                    "The TV never answered",
                    "Nobody pressed OK on the remote within 60 seconds.",
                    "Keep the remote in your hand — the prompt appears a second or two after connecting.",
                )
            } else {
                Failure::new(
                    "Pairing failed",
                    e,
                    "Try again. If it keeps failing, switch the TV off and on, then scan again.",
                )
            }
        })?;

    if !key.is_empty() && key != stored {
        keystore::save(ip, &key);
    }
    let _ = tx.send(Event::Log("paired".into()));
    let _ = tx.send(Event::Step(2));

    if cancel.load(Ordering::Relaxed) {
        return Ok(());
    }

    // Prefer a launcher that is actually installed; `listApps` is sometimes
    // refused, in which case fall back to the known candidates in order.
    let installed = tv.installed_apps();
    if !installed.is_empty() {
        let _ = tx.send(Event::Log(format!(
            "TV reports {} installed apps",
            installed.len()
        )));
    }
    let mut attempts: Vec<(&str, &str)> = ssap::TARGET_APPS
        .iter()
        .filter(|(id, _, _)| installed.is_empty() || installed.iter().any(|i| i == id))
        .map(|(id, param, _)| (*id, *param))
        .collect();
    if attempts.is_empty() {
        attempts = ssap::TARGET_APPS
            .iter()
            .map(|(id, param, _)| (*id, *param))
            .collect();
    }

    let mut launched = false;
    for (app_id, param) in attempts.iter().take(3) {
        let _ = tx.send(Event::Log(format!("launching {app_id}")));
        match tv.launch(app_id, param, &url) {
            Ok(()) => {
                let _ = tx.send(Event::Log(format!("launched {app_id}")));
                launched = true;
                break;
            }
            Err(e) => {
                let _ = tx.send(Event::Log(format!("{app_id}: {e}")));
            }
        }
    }
    if !launched {
        return Err(Failure::new(
            "The TV would not open the installer",
            "Every launcher app this tool knows how to use was refused.",
            "This usually means the firmware is patched. Check cani.rootmy.tv for your model. On webOS 3.5–4.x, use dejavuln-autoroot instead.",
        ));
    }

    let _ = tx.send(Event::Step(3));

    // Success is Homebrew Channel actually existing, not the files being served.
    let deadline = Instant::now() + Duration::from_secs(180);
    let mut announced = false;
    loop {
        if cancel.load(Ordering::Relaxed) {
            return Ok(());
        }
        if tv.app_installed(ssap::HB_CHANNEL) {
            break;
        }
        if Instant::now() > deadline {
            return Err(Failure::new(
                "Homebrew Channel did not appear",
                format!(
                    "The installer reached the TV ({} of {} files downloaded) but the app never showed up.",
                    tracker.count(),
                    tracker.total()
                ),
                "Look at the TV screen — it may be showing an error or a reboot prompt. If it says the service is patched, this exploit will not work on that firmware.",
            ));
        }
        if !announced && tracker.count() == tracker.total() {
            let _ = tx.send(Event::Log(
                "all installer files delivered; waiting for the install to finish".into(),
            ));
            announced = true;
        }
        thread::sleep(Duration::from_secs(2));
    }

    let _ = tx.send(Event::Step(4));
    tv.close();
    drop(server);
    let _ = tx.send(Event::Done);
    Ok(())
}
