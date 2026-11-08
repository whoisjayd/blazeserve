//! Directory listing HTML.

use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use std::fmt::Write as _;
use std::time::{SystemTime, UNIX_EPOCH};

const CSS: &str = include_str!("ui/index.css");
const JS: &str = include_str!("ui/index.js");

/// Everything except RFC 3986 unreserved characters is encoded.
const COMPONENT: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

const SPRITE: &str = concat!(
    r#"<svg width="0" height="0" style="position:absolute" aria-hidden="true" focusable="false">"#,
    r#"<symbol id="i-folder" viewBox="0 0 24 24"><path d="M20 20a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.9a2 2 0 0 1-1.69-.9L9.6 3.9A2 2 0 0 0 7.93 3H4a2 2 0 0 0-2 2v13a2 2 0 0 0 2 2Z"/></symbol>"#,
    r#"<symbol id="i-file" viewBox="0 0 24 24"><path d="M15 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7Z"/><path d="M14 2v4a2 2 0 0 0 2 2h4"/></symbol>"#,
    "</svg>"
);

#[derive(Debug, Clone)]
pub struct Entry {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
    pub modified: Option<SystemTime>,
}

pub fn human_size(n: u64) -> String {
    let mut x = n as f64;
    for unit in ["B", "KB", "MB", "GB", "TB", "PB", "EB"] {
        if x < 1024.0 {
            return format!("{x:.2}{unit}");
        }
        x /= 1024.0;
    }
    format!("{x:.2}ZB")
}

fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(c),
        }
    }
    out
}

fn encode(s: &str) -> String {
    utf8_percent_encode(s, COMPONENT).to_string()
}

fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

fn unix_seconds(t: SystemTime) -> Option<i64> {
    t.duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_secs()).ok())
}

fn format_utc(secs: i64) -> String {
    let (y, m, d) = civil_from_days(secs.div_euclid(86_400));
    let rem = secs.rem_euclid(86_400);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}",
        rem / 3600,
        rem % 3600 / 60
    )
}

fn kind_label(e: &Entry) -> String {
    if e.is_dir {
        return "Folder".into();
    }
    match e.name.rsplit_once('.') {
        Some((stem, ext))
            if !stem.is_empty()
                && (1..=8).contains(&ext.len())
                && ext.bytes().all(|b| b.is_ascii_alphanumeric()) =>
        {
            format!(".{}", ext.to_ascii_lowercase())
        }
        _ => "File".into(),
    }
}

fn icon(id: &str) -> String {
    format!(r##"<svg class="icon" aria-hidden="true" focusable="false"><use href="#{id}"/></svg>"##)
}

/// `rel_path` is unescaped, `/`-separated, without a leading slash. Names are
/// escaped and path components percent-encoded; the script only ever sees a name
/// through an attribute read back with `dataset`, never as markup.
pub fn render_directory_index(rel_path: &str, entries: &[Entry], allow_upload: bool) -> String {
    let parts: Vec<&str> = rel_path.split('/').filter(|p| !p.is_empty()).collect();
    let encoded: Vec<String> = parts.iter().map(|p| encode(p)).collect();
    let mut current_url = String::from("/");
    for p in &encoded {
        current_url.push_str(p);
        current_url.push('/');
    }
    let display_path = format!("/{}", parts.join("/"));
    let display_esc = escape(&display_path);

    let mut sorted: Vec<&Entry> = entries.iter().collect();
    sorted.sort_by_cached_key(|e| (!e.is_dir, e.name.to_lowercase()));

    let mut out = String::with_capacity(4096 + entries.len() * 320);
    let _ = write!(
        out,
        concat!(
            "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n",
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n",
            "<meta name=\"color-scheme\" content=\"dark light\">\n",
            "<title>{} - BlazeServe</title>\n<style>{}</style>\n</head>\n<body>\n{}\n",
            "<main class=\"page\">\n<h1 class=\"sr-only\">Index of {}</h1>\n",
        ),
        display_esc, CSS, SPRITE, display_esc
    );

    out.push_str("<nav class=\"crumbs\" aria-label=\"Breadcrumb\"><ol>");
    if parts.is_empty() {
        out.push_str("<li><span aria-current=\"page\">root</span></li>");
    } else {
        out.push_str("<li><a href=\"/\">root</a></li>");
        let mut href = String::from("/");
        for (i, part) in parts.iter().enumerate() {
            href.push_str(&encoded[i]);
            href.push('/');
            if i + 1 == parts.len() {
                let _ = write!(
                    out,
                    "<li><span aria-current=\"page\">{}</span></li>",
                    escape(part)
                );
            } else {
                let _ = write!(
                    out,
                    "<li><a href=\"{}\">{}</a></li>",
                    escape(&href),
                    escape(part)
                );
            }
        }
    }
    out.push_str("</ol></nav>\n");

    if allow_upload {
        let _ = write!(
            out,
            concat!(
                "<section class=\"drop\" id=\"drop\" data-base=\"/__upload__{}\" aria-label=\"Upload\">",
                "<p>Drop files to upload to <code>{}</code></p>",
                "<button type=\"button\" class=\"btn\" id=\"pick\">Choose files</button>",
                "<input type=\"file\" id=\"picker\" multiple hidden>",
                "<ul class=\"uploads\" id=\"uploads\" aria-live=\"polite\"></ul></section>\n",
            ),
            escape(&current_url),
            display_esc
        );
    }

    let count = if entries.len() == 1 {
        "1 item".to_owned()
    } else {
        format!("{} items", entries.len())
    };
    let _ = write!(
        out,
        concat!(
            "<div class=\"tools\"><div class=\"filter\">",
            "<label class=\"sr-only\" for=\"filter\">Filter</label>",
            "<input id=\"filter\" type=\"search\" placeholder=\"Filter\" autocomplete=\"off\" spellcheck=\"false\">",
            "<kbd aria-hidden=\"true\">/</kbd></div><span class=\"count\" id=\"count\">{}</span></div>\n",
        ),
        count
    );

    out.push_str(concat!(
        "<div class=\"card\"><table><caption class=\"sr-only\">Files</caption><thead><tr>",
        "<th scope=\"col\" class=\"col-name\" data-key=\"name\" aria-sort=\"ascending\"><button type=\"button\">Name</button></th>",
        "<th scope=\"col\" class=\"col-size\" data-key=\"size\"><button type=\"button\">Size</button></th>",
        "<th scope=\"col\" class=\"col-mod\" data-key=\"mtime\"><button type=\"button\">Modified</button></th>",
        "<th scope=\"col\" class=\"col-type\">Type</th>",
        "</tr></thead>\n<tbody id=\"entries\">\n",
    ));

    if !parts.is_empty() {
        let parent = if encoded.len() > 1 {
            format!("/{}/", encoded[..encoded.len() - 1].join("/"))
        } else {
            "/".to_owned()
        };
        let _ = writeln!(
            out,
            concat!(
                "<tr class=\"parent\"><td class=\"col-name\"><a href=\"{}\" aria-label=\"Parent folder\">{}",
                "<span class=\"name\">..</span></a></td><td class=\"col-size num\">-</td>",
                "<td class=\"col-mod num\">-</td><td class=\"col-type\">Folder</td></tr>",
            ),
            escape(&parent),
            icon("i-folder")
        );
    }

    for e in &sorted {
        let mut href = format!("{current_url}{}", encode(&e.name));
        if e.is_dir {
            href.push('/');
        }
        let secs = e.modified.and_then(unix_seconds);
        let _ = writeln!(
            out,
            concat!(
                "<tr class=\"entry\" data-name=\"{n}\" data-dir=\"{d}\" data-size=\"{s}\" data-mtime=\"{t}\">",
                "<td class=\"col-name\"><a href=\"{h}\">{i}<span class=\"name\">{n}</span></a></td>",
                "<td class=\"col-size num\">{z}</td><td class=\"col-mod num\">{m}</td>",
                "<td class=\"col-type\">{k}</td></tr>",
            ),
            n = escape(&e.name),
            d = u8::from(e.is_dir),
            s = if e.is_dir { 0 } else { e.size },
            t = secs.unwrap_or(-1),
            h = escape(&href),
            i = icon(if e.is_dir { "i-folder" } else { "i-file" }),
            z = if e.is_dir {
                "-".to_owned()
            } else {
                human_size(e.size)
            },
            m = secs.map_or_else(|| "-".to_owned(), format_utc),
            k = kind_label(e),
        );
    }

    if entries.is_empty() {
        out.push_str("<tr class=\"empty\"><td colspan=\"4\">This folder is empty</td></tr>\n");
    } else {
        out.push_str("<tr class=\"nomatch\" id=\"no-match\" hidden><td colspan=\"4\">No files match</td></tr>\n");
    }

    let _ = write!(
        out,
        "</tbody></table></div>\n<footer>BlazeServe {}</footer>\n</main>\n<script>{}</script>\n</body>\n</html>\n",
        crate::VERSION,
        JS
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn human_size_matches_python_contract() {
        assert_eq!(human_size(100), "100.00B");
        assert_eq!(human_size(1024), "1.00KB");
        assert_eq!(human_size(1536), "1.50KB");
        assert_eq!(human_size(1024 * 1024), "1.00MB");
        assert_eq!(human_size(1024 * 1024 * 1024), "1.00GB");
        assert_eq!(human_size(0), "0.00B");
        assert_eq!(human_size(u64::MAX), "16.00EB");
    }

    #[test]
    fn civil_dates() {
        assert_eq!(format_utc(0), "1970-01-01 00:00");
        assert_eq!(format_utc(951_782_400), "2000-02-29 00:00");
        assert_eq!(format_utc(1_709_210_096), "2024-02-29 12:34");
        assert_eq!(format_utc(-86_400), "1969-12-31 00:00");
        assert_eq!(format_utc(4_102_444_799), "2099-12-31 23:59");
    }

    #[test]
    fn kind_labels() {
        let f = |n: &str| Entry {
            name: n.into(),
            is_dir: false,
            size: 0,
            modified: None,
        };
        assert_eq!(kind_label(&f("a.TAR")), ".tar");
        assert_eq!(kind_label(&f(".bashrc")), "File");
        assert_eq!(kind_label(&f("noext")), "File");
        assert_eq!(kind_label(&f("x.toolongext1")), "File");
    }
}
