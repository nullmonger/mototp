use crate::entry::Entry;

// Indices point into the full list, so a caller acts on the stored entry
// even when the view shows only a subset.
pub fn filter_by_tag(entries: &[Entry], tag: &str) -> Vec<usize> {
    entries
        .iter()
        .enumerate()
        .filter(|(_, entry)| entry.tags.iter().any(|t| t == tag))
        .map(|(index, _)| index)
        .collect()
}

pub fn visible_indices(entries: &[Entry], active_tag: Option<&str>) -> Vec<usize> {
    match active_tag {
        Some(tag) => filter_by_tag(entries, tag),
        None => (0..entries.len()).collect(),
    }
}

pub fn all_tags(entries: &[Entry]) -> Vec<String> {
    let mut tags: Vec<String> = entries
        .iter()
        .flat_map(|entry| entry.tags.iter().cloned())
        .collect();
    tags.sort();
    tags.dedup();
    tags
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::OtpKind;
    use crate::otp::Algorithm;

    fn entry(label: &str, tags: &[&str]) -> Entry {
        Entry {
            issuer: None,
            label: label.into(),
            display_name: None,
            secret: b"12345678901234567890".to_vec(),
            algorithm: Algorithm::Sha1,
            digits: 6,
            kind: OtpKind::Totp { period: 30 },
            tags: tags.iter().map(|tag| tag.to_string()).collect(),
        }
    }

    // An entry in several groups must show up under each of its tags.
    #[test]
    fn filter_returns_matching_subset() {
        let list = vec![
            entry("a", &["work"]),
            entry("b", &["home"]),
            entry("c", &["work", "home"]),
        ];
        assert_eq!(filter_by_tag(&list, "work"), vec![0, 2]);
        assert_eq!(filter_by_tag(&list, "home"), vec![1, 2]);
        assert_eq!(filter_by_tag(&list, "absent"), Vec::<usize>::new());
    }

    #[test]
    fn no_active_tag_shows_everything() {
        let list = vec![entry("a", &["work"]), entry("b", &[])];
        assert_eq!(visible_indices(&list, None), vec![0, 1]);
        assert_eq!(visible_indices(&list, Some("work")), vec![0]);
    }

    #[test]
    fn all_tags_sorted_and_deduplicated() {
        let list = vec![entry("a", &["work", "mail"]), entry("b", &["mail", "home"])];
        assert_eq!(all_tags(&list), vec!["home", "mail", "work"]);
    }
}
