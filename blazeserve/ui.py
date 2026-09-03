"""Modern responsive HTML5 directory listing UI."""

from __future__ import annotations

import html
import os

from blazeserve.utils import human_size


def render_directory_index(
    dir_path: str,
    rel_path: str,
    entries: list[os.DirEntry],
    allow_upload: bool = False,
) -> bytes:
    """Render a polished, mobile-responsive directory index with search and file icons."""
    display_path = "/" + rel_path.strip("/")
    if display_path == "//":
        display_path = "/"
    title = f"Index of {html.escape(display_path)}"

    # Sort directories first, then files alphabetically
    sorted_entries = sorted(entries, key=lambda e: (not e.is_dir(), e.name.lower()))

    rows = []
    if rel_path and rel_path != "/":
        parent = os.path.dirname(rel_path.rstrip("/")) or "/"
        rows.append(
            '<tr><td style="text-align:center">📁</td>'
            f'<td><a href="{html.escape(parent)}">.. (Parent Directory)</a></td>'
            '<td>-</td><td>Directory</td></tr>'
        )

    for entry in sorted_entries:
        try:
            stat = entry.stat()
            is_dir = entry.is_dir()
            icon = "📁" if is_dir else "📄"
            size_str = "-" if is_dir else human_size(stat.st_size)
            name_esc = html.escape(entry.name)
            href = f"{name_esc}/" if is_dir else name_esc
            type_str = "Directory" if is_dir else "File"
            rows.append(
                f'<tr class="entry-row">'
                f'  <td style="text-align:center">{icon}</td>'
                f'  <td><a class="entry-link" href="{href}">{name_esc}</a></td>'
                f'  <td>{size_str}</td>'
                f'  <td>{type_str}</td>'
                f'</tr>'
            )
        except OSError:
            continue

    body_rows = "\n".join(rows)
    upload_ui = ""
    if allow_upload:
        upload_ui = """
    <div class="upload-box" id="dropzone">
      <span>Drag & drop files here or click to upload</span>
      <input type="file" id="fileInput" style="display:none" multiple>
    </div>
    """

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{title} — BlazeServe</title>
  <style>
    :root {{
      --bg: #0d1117; --surface: #161b22; --border: #30363d;
      --text: #c9d1d9; --accent: #58a6ff; --hover: #21262d;
    }}
    @media (prefers-color-scheme: light) {{
      :root {{
        --bg: #ffffff; --surface: #f6f8fa; --border: #d0d7de;
        --text: #24292f; --accent: #0969da; --hover: #eaeef2;
      }}
    }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background: var(--bg); color: var(--text); margin: 0; padding: 2rem;
    }}
    .container {{ max-width: 960px; margin: 0 auto; }}
    header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); padding-bottom: 1rem; margin-bottom: 1.5rem; }}
    h1 {{ margin: 0; font-size: 1.4rem; }}
    .search-box {{
      width: 100%; padding: 0.6rem 1rem; margin-bottom: 1rem; box-sizing: border-box;
      background: var(--surface); border: 1px solid var(--border); color: var(--text); border-radius: 6px; font-size: 0.95rem;
    }}
    table {{ width: 100%; border-collapse: collapse; text-align: left; }}
    th, td {{ padding: 0.6rem 0.8rem; border-bottom: 1px solid var(--border); }}
    th {{ background: var(--surface); font-weight: 600; }}
    tr.entry-row:hover {{ background: var(--hover); }}
    a {{ color: var(--accent); text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}
    .upload-box {{
      border: 2px dashed var(--border); border-radius: 8px; padding: 1.5rem; text-align: center;
      margin-bottom: 1.5rem; background: var(--surface); cursor: pointer;
    }}
    .upload-box:hover {{ border-color: var(--accent); }}
    footer {{ margin-top: 2rem; font-size: 0.85rem; color: #8b949e; text-align: center; }}
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>⚡ {title}</h1>
      <span>BlazeServe 0.3.0</span>
    </header>
    {upload_ui}
    <input type="text" id="search" class="search-box" placeholder="Filter files in directory..." autofocus>
    <table>
      <thead>
        <tr><th style="width:36px"></th><th>Name</th><th style="width:120px">Size</th><th style="width:100px">Type</th></tr>
      </thead>
      <tbody id="entries">
        {body_rows}
      </tbody>
    </table>
    <footer>⚡ Ultra-Fast HTTP File Server • Production-Ready</footer>
  </div>
  <script>
    document.getElementById('search').addEventListener('input', function(e) {{
      const q = e.target.value.toLowerCase();
      document.querySelectorAll('.entry-row').forEach(row => {{
        const text = row.querySelector('.entry-link').innerText.toLowerCase();
        row.style.display = text.includes(q) ? '' : 'none';
      }});
    }});
  </script>
</body>
</html>"""
    return html_content.encode("utf-8")
