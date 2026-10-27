//! Messages shared between the worker thread and the UI thread.

/// One discovered TV, as shown in the list.
#[derive(Clone, Debug)]
pub struct TvInfo {
    pub ip: String,
    pub name: String,
    pub detail: String,
    pub badge: String,
}

/// Everything the worker reports back to the UI.
#[derive(Debug)]
pub enum Event {
    ScanStarted,
    ScanProgress { done: usize, total: usize },
    TvFound(TvInfo),
    ScanFinished,

    /// Number of completed steps in the install progress list (0..=4).
    Step(u32),
    /// Seconds left, and the total window, while waiting for the TV prompt.
    PairCountdown { left: u32, total: u32 },
    /// Installer assets handed to the TV so far.
    Files { served: usize, total: usize },

    /// URL to open in the TV's browser to prove the TV can reach this computer.
    TestUrl(String),

    Log(String),
    Done,
    Failed {
        title: String,
        body: String,
        hint: String,
    },
}

/// Everything the UI asks the worker to do.
#[derive(Debug)]
pub enum Command {
    Scan,
    Run {
        ip: String,
        local_ip: String,
        debug: bool,
    },
    Test,
    Reboot(String),
    LaunchHb(String),
}
