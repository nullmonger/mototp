// The secret itself never reaches the markup.

use std::time::{SystemTime, UNIX_EPOCH};

use dioxus::prelude::*;

use crate::entry::{Entry, LiveCode, OtpKind};
use crate::otp::OtpError;
use crate::store::Store;

pub fn app() -> Element {
    let mut entries = use_signal(Vec::<Entry>::new);
    let mut load_error = use_signal(|| None::<String>);
    let mut save_error = use_signal(|| None::<String>);
    let store = use_signal(Store::open_default);

    use_hook(|| match &*store.read() {
        Ok(opened) => match opened.load() {
            Ok(list) => entries.set(list),
            Err(error) => load_error.set(Some(error.to_string())),
        },
        Err(error) => load_error.set(Some(error.to_string())),
    });

    let mut now = use_signal(unix_now);
    use_future(move || async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            now.set(unix_now());
        }
    });

    // FIXME: the handler and the list key identify an entry by its position;
    // this breaks once the visible list is a filtered subset of the stored one.
    let mut advance_hotp = move |index: usize| {
        {
            let mut list = entries.write();
            let Some(entry) = list.get_mut(index) else {
                return;
            };
            let OtpKind::Hotp { counter } = &mut entry.kind else {
                return;
            };
            *counter = counter.saturating_add(1);
        }
        let saved = match &*store.read() {
            Ok(opened) => opened.save(&entries.read()).map_err(|e| e.to_string()),
            Err(error) => Err(error.to_string()),
        };
        // No rollback if the save fails: the code is already on screen,
        // and rolling the counter back would hand out the same code twice.
        save_error.set(
            saved
                .err()
                .map(|error| format!("The counter advanced but saving it failed: {error}")),
        );
    };

    rsx! {
        div {
            if let Some(error) = load_error() {
                p { "Could not load the stored entries: {error}" }
            } else {
                if let Some(error) = save_error() {
                    p { "{error}" }
                }
                if entries.read().is_empty() {
                    p { "No entries yet." }
                }
                ul {
                    for (index, entry) in entries().into_iter().enumerate() {
                        li { key: "{index}",
                            if let Some(issuer) = entry.issuer.clone() {
                                span { "{issuer}: " }
                            }
                            span { "{entry.display_label()} " }
                            {code_cell(&entry, now())}
                            if matches!(entry.kind, OtpKind::Hotp { .. }) {
                                button { onclick: move |_| advance_hotp(index), "Next code" }
                            }
                        }
                    }
                }
            }
        }
    }
}

fn code_cell(entry: &Entry, now: Result<u64, OtpError>) -> Element {
    match now.and_then(|time| entry.live_code_at(time)) {
        Ok(LiveCode::Totp { code, remaining }) => rsx! {
            strong { "{code}" }
            span { " {remaining}s" }
        },
        Ok(LiveCode::Hotp { code }) => rsx! {
            strong { "{code}" }
        },
        Err(error) => rsx! {
            span { "{error}" }
        },
    }
}

fn unix_now() -> Result<u64, OtpError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| OtpError::ClockBeforeEpoch)
}
