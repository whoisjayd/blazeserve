use blazeserve::ui::{Entry, render_directory_index};
use std::time::{Duration, UNIX_EPOCH};

fn file(name: &str, size: u64) -> Entry {
    Entry {
        name: name.into(),
        is_dir: false,
        size,
        modified: Some(UNIX_EPOCH + Duration::from_secs(1_709_210_096)),
    }
}

fn dir(name: &str) -> Entry {
    Entry {
        name: name.into(),
        is_dir: true,
        size: 0,
        modified: None,
    }
}

fn hrefs(html: &str) -> Vec<String> {
    html.split("<tr class=\"entry\"")
        .skip(1)
        .map(|row| {
            let start = row.find("<a href=\"").unwrap() + 9;
            let end = row[start..].find('"').unwrap();
            row[start..start + end].to_owned()
        })
        .collect()
}

#[test]
fn hostile_names_are_escaped_everywhere() {
    let names = [
        "<script>alert(1)</script>",
        "\"onmouseover=\"x",
        "a'b&c",
        "</td><img src=x>",
    ];
    let entries: Vec<Entry> = names.iter().map(|n| file(n, 1)).collect();
    let html = render_directory_index("sub", &entries, false);
    assert!(!html.contains("<script>alert(1)"));
    assert!(!html.contains("<img src=x>"));
    assert!(!html.contains("\"onmouseover=\"x"));
    assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
    assert!(html.contains("&quot;onmouseover=&quot;x"));
    assert!(html.contains("a&#x27;b&amp;c"));
    assert_eq!(
        html.matches("<script>").count(),
        1,
        "only the bundled script remains"
    );
}

#[test]
fn hrefs_percent_encode_special_characters() {
    let entries = vec![
        file("a b#c?d%e.txt", 1),
        file("caf\u{e9}.txt", 1),
        dir("x y"),
    ];
    let h = hrefs(&render_directory_index("dir one/sub", &entries, false));
    assert_eq!(h[0], "/dir%20one/sub/x%20y/");
    assert_eq!(h[1], "/dir%20one/sub/a%20b%23c%3Fd%25e.txt");
    assert_eq!(h[2], "/dir%20one/sub/caf%C3%A9.txt");
}

#[test]
fn path_title_and_breadcrumbs_are_escaped() {
    let html = render_directory_index("<b>/x\"y", &[], false);
    assert!(!html.contains("<b>"));
    assert!(html.contains("&lt;b&gt;"));
    assert!(html.contains("%3Cb%3E/"));
}

#[test]
fn directories_sort_first_then_case_insensitive() {
    let entries = vec![
        file("b.txt", 1),
        file("A.txt", 1),
        dir("zeta"),
        dir("Alpha"),
    ];
    let h = hrefs(&render_directory_index("", &entries, false));
    assert_eq!(h, ["/Alpha/", "/zeta/", "/A.txt", "/b.txt"]);
}

#[test]
fn parent_row_only_below_root() {
    assert!(!render_directory_index("", &[], false).contains("class=\"parent\""));
    let html = render_directory_index("a/b", &[], false);
    assert!(html.contains("<a href=\"/a/\" aria-label=\"Parent folder\">"));
    assert!(
        render_directory_index("a", &[], false)
            .contains("<a href=\"/\" aria-label=\"Parent folder\">")
    );
}

#[test]
fn empty_folder_shows_empty_state() {
    let html = render_directory_index("", &[], false);
    assert!(html.contains("This folder is empty"));
    assert!(!html.contains("id=\"no-match\""));
    assert!(render_directory_index("", &[file("a", 1)], false).contains("id=\"no-match\""));
}

#[test]
fn upload_box_only_when_enabled() {
    let off = render_directory_index("a b", &[], false);
    assert!(!off.contains("id=\"drop\"") && !off.contains("__upload__"));
    let on = render_directory_index("a b", &[], true);
    assert!(on.contains("data-base=\"/__upload__/a%20b/\""));
    let root = render_directory_index("", &[], true);
    assert!(root.contains("data-base=\"/__upload__/\""));
}

#[test]
fn sizes_and_dates_are_formatted() {
    let html = render_directory_index("", &[file("a.zip", 1536)], false);
    assert!(html.contains("1.50KB"));
    assert!(html.contains("2024-02-29 12:34"));
    assert!(html.contains(">.zip<"));
    assert!(html.contains("data-mtime=\"1709210096\""));
}

#[test]
fn version_comes_from_the_crate() {
    let html = render_directory_index("", &[], false);
    assert!(html.contains(&format!(
        "<footer>BlazeServe {}</footer>",
        blazeserve::VERSION
    )));
    assert!(!html.contains("Production-Ready") && !html.contains("Ultra-Fast"));
}

#[test]
fn chrome_has_no_emoji_or_symbols() {
    let html = render_directory_index("sub", &[file("plain.txt", 1), dir("d")], true);
    let offenders: Vec<char> = html.chars().filter(|c| *c as u32 > 0x2000).collect();
    assert!(offenders.is_empty(), "unexpected symbols: {offenders:?}");
}

#[test]
fn unicode_names_survive_unchanged_in_text() {
    let html = render_directory_index("", &[file("\u{1F4C4}\u{65E5}\u{672C}.txt", 1)], false);
    assert!(html.contains("<span class=\"name\">\u{1F4C4}\u{65E5}\u{672C}.txt</span>"));
}
