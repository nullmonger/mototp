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

// Case-insensitive match over everything the user can see in the list.
pub fn search(entries: &[Entry], text: &str) -> Vec<usize> {
    let needle = text.trim().to_lowercase();
    if needle.is_empty() {
        return (0..entries.len()).collect();
    }
    entries
        .iter()
        .enumerate()
        .filter(|(_, entry)| matches_search(entry, &needle))
        .map(|(index, _)| index)
        .collect()
}

fn matches_search(entry: &Entry, needle_lower: &str) -> bool {
    let hit = |text: &str| text.to_lowercase().contains(needle_lower);
    hit(&entry.label)
        || entry.issuer.as_deref().is_some_and(hit)
        || entry.display_name.as_deref().is_some_and(hit)
        || entry.tags.iter().any(|tag| hit(tag))
}

pub fn visible_indices(
    entries: &[Entry],
    active_tag: Option<&str>,
    search_text: &str,
) -> Vec<usize> {
    let mut indices = match active_tag {
        Some(tag) => filter_by_tag(entries, tag),
        None => (0..entries.len()).collect(),
    };
    let matched = search(entries, search_text);
    indices.retain(|index| matched.contains(index));
    indices
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
        assert_eq!(visible_indices(&list, None, ""), vec![0, 1]);
        assert_eq!(visible_indices(&list, Some("work"), ""), vec![0]);
    }

    #[test]
    fn search_matches_each_field_case_insensitively() {
        let mut list = vec![entry("alice", &["work"]), entry("bob", &[])];
        list[0].issuer = Some("Example".into());
        list[1].display_name = Some("Backup phone".into());

        assert_eq!(search(&list, "ALI"), vec![0]); // label
        assert_eq!(search(&list, "example"), vec![0]); // issuer
        assert_eq!(search(&list, "backup"), vec![1]); // display_name
        assert_eq!(search(&list, "WORK"), vec![0]); // tag
        assert_eq!(search(&list, ""), vec![0, 1]);
        assert_eq!(search(&list, "zzz"), Vec::<usize>::new());
    }

    #[test]
    fn search_combines_with_tag_filter() {
        let list = vec![
            entry("alice", &["work"]),
            entry("albert", &["home"]),
            entry("bob", &["work"]),
        ];
        assert_eq!(visible_indices(&list, Some("work"), "al"), vec![0]);
    }

    #[test]
    fn all_tags_sorted_and_deduplicated() {
        let list = vec![entry("a", &["work", "mail"]), entry("b", &["mail", "home"])];
        assert_eq!(all_tags(&list), vec!["home", "mail", "work"]);
    }
}
