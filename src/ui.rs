// Stored secrets never reach the markup; the add form is the exception:
// it echoes the otpauth URI, secret included, while it is being typed.

use std::time::{SystemTime, UNIX_EPOCH};

use dioxus::prelude::*;

use crate::entry::{Entry, LiveCode, OtpKind};
use crate::otp::OtpError;
use crate::otpauth;
use crate::query;
use crate::store::Store;

pub fn app() -> Element {
    let mut entries = use_signal(Vec::<Entry>::new);
    let mut load_error = use_signal(|| None::<String>);
    let mut save_error = use_signal(|| None::<String>);
    let mut active_tag = use_signal(|| None::<String>);
    let mut search_text = use_signal(String::new);
    let mut add_uri = use_signal(String::new);
    let mut add_error = use_signal(|| None::<String>);
    let mut pending_delete = use_signal(|| None::<usize>);
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

    let mut persist = move || {
        let saved = match &*store.read() {
            Ok(opened) => opened.save(&entries.read()).map_err(|e| e.to_string()),
            Err(error) => Err(error.to_string()),
        };
        save_error.set(
            saved
                .err()
                .map(|error| format!("Saving failed, the change is not on disk: {error}")),
        );
    };

    let mut advance_hotp = move |index: usize| {
        {
            let mut list = entries.write();
            let Some(entry) = list.get_mut(index) else {
                return;
            };
            let OtpKind::Hotp { counter } = &mut entry.kind else {
                return;
            };
            // No rollback if the save fails: the code is already on screen,
            // and rolling the counter back would hand out the same code twice.
            *counter = counter.saturating_add(1);
        }
        persist();
    };

    // If a change stripped the active tag from its last entry,
    // drop the filter: otherwise the view is stuck empty with nothing to reset it.
    let mut drop_stale_tag = move || {
        let tag_gone = active_tag.peek().as_ref().is_some_and(|tag| {
            !entries
                .read()
                .iter()
                .any(|entry| entry.tags.iter().any(|t| t == tag))
        });
        if tag_gone {
            active_tag.set(None);
        }
    };

    let mut set_tags = move |index: usize, raw: String| {
        {
            let mut list = entries.write();
            let Some(entry) = list.get_mut(index) else {
                return;
            };
            let mut tags: Vec<String> = Vec::new();
            for tag in raw.split_whitespace() {
                if !tags.iter().any(|t| t == tag) {
                    tags.push(tag.to_string());
                }
            }
            entry.tags = tags;
        }
        drop_stale_tag();
        persist();
    };

    let mut set_display_name = move |index: usize, raw: String| {
        {
            let mut list = entries.write();
            let Some(entry) = list.get_mut(index) else {
                return;
            };
            let trimmed = raw.trim();
            entry.display_name = if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            };
        }
        persist();
    };

    let mut add_entry = move || {
        let uri = add_uri.peek().trim().to_string();
        if uri.is_empty() {
            return;
        }
        match otpauth::parse(&uri) {
            Ok(entry) => {
                entries.write().push(entry);
                add_uri.set(String::new());
                add_error.set(None);
                // The new entry has no tags, so an active filter or search
                // would hide it and the add would look like a silent failure.
                active_tag.set(None);
                search_text.set(String::new());
                persist();
            }
            Err(error) => add_error.set(Some(error.to_string())),
        }
    };

    let mut remove_entry = move |index: usize| {
        // Only the armed row may confirm: a stale click that arrives after
        // the list shifted must not remove whatever moved onto this index.
        if *pending_delete.peek() != Some(index) {
            return;
        }
        {
            let mut list = entries.write();
            if index >= list.len() {
                return;
            }
            list.remove(index);
        }
        pending_delete.set(None);
        drop_stale_tag();
        persist();
    };

    let all_tags = query::all_tags(&entries.read());
    let visible = query::visible_indices(
        &entries.read(),
        active_tag.read().as_deref(),
        &search_text.read(),
    );

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
                } else if visible.is_empty() {
                    p { "No matches." }
                }
                div {
                    input {
                        value: "{add_uri}",
                        placeholder: "otpauth:// URI",
                        oninput: move |event| add_uri.set(event.value()),
                    }
                    button { onclick: move |_| add_entry(), "Add" }
                    if let Some(error) = add_error() {
                        span { " {error}" }
                    }
                }
                input {
                    value: "{search_text}",
                    placeholder: "search",
                    oninput: move |event| {
                        search_text.set(event.value());
                        pending_delete.set(None);
                    },
                }
                div {
                    for tag in all_tags {
                        {
                            let is_active = active_tag.read().as_deref() == Some(tag.as_str());
                            let shown = if is_active { format!("[{tag}]") } else { tag.clone() };
                            rsx! {
                                button {
                                    onclick: move |_| {
                                        let clicked = tag.clone();
                                        let same = active_tag.peek().as_deref() == Some(clicked.as_str());
                                        active_tag.set(if same { None } else { Some(clicked) });
                                        pending_delete.set(None);
                                    },
                                    "{shown}"
                                }
                            }
                        }
                    }
                }
                ul {
                    for index in visible {
                        {
                            let entry = entries.read()[index].clone();
                            let tags_text = entry.tags.join(" ");
                            let name_text = entry.display_name.clone().unwrap_or_default();
                            rsx! {
                                // FIXME: the list key is the storage index, not a stable identity;
                                // after a deletion the DOM rows can inherit a neighbour's focus/input.
                                li { key: "{index}",
                                    if let Some(issuer) = entry.issuer.clone() {
                                        span { "{issuer}: " }
                                    }
                                    span { "{entry.display_label()} " }
                                    {code_cell(&entry, now())}
                                    if matches!(entry.kind, OtpKind::Hotp { .. }) {
                                        button { onclick: move |_| advance_hotp(index), "Next code" }
                                    }
                                    // FIXME: the name and tags inputs normalize their value on commit;
                                    // the field may keep the raw text while the state holds the clean one.
                                    input {
                                        value: "{name_text}",
                                        placeholder: "name",
                                        onchange: move |event| set_display_name(index, event.value()),
                                    }
                                    input {
                                        value: "{tags_text}",
                                        placeholder: "tags",
                                        onchange: move |event| set_tags(index, event.value()),
                                    }
                                    if pending_delete() == Some(index) {
                                        button { onclick: move |_| remove_entry(index), "Confirm delete" }
                                    } else {
                                        button { onclick: move |_| pending_delete.set(Some(index)), "Delete" }
                                    }
                                }
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
