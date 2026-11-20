(function () {
  "use strict";

  var body = document.getElementById("entries");
  var rows = Array.prototype.slice.call(body.querySelectorAll("tr.entry"));
  var input = document.getElementById("filter");
  var count = document.getElementById("count");
  var none = document.getElementById("no-match");
  var total = rows.length;
  var keys = rows.map(function (r) {
    return r.dataset.name.toLowerCase();
  });
  var meta = rows.map(function (r) {
    return {
      row: r,
      dir: r.dataset.dir === "1",
      name: r.dataset.name.toLowerCase(),
      size: Number(r.dataset.size),
      mtime: Number(r.dataset.mtime),
    };
  });

  function label(n) {
    return n + (n === 1 ? " item" : " items");
  }

  function applyFilter() {
    var q = input.value.trim().toLowerCase();
    var shown = 0;
    for (var i = 0; i < rows.length; i++) {
      var hit = q === "" || keys[i].indexOf(q) !== -1;
      rows[i].hidden = !hit;
      if (hit) shown++;
    }
    if (none) none.hidden = shown > 0;
    count.textContent = q === "" ? label(total) : shown + " of " + label(total);
  }

  input.addEventListener("input", applyFilter);
  input.addEventListener("keydown", function (e) {
    if (e.key !== "Escape") return;
    if (input.value !== "") {
      input.value = "";
      applyFilter();
    } else {
      input.blur();
    }
  });

  document.addEventListener("keydown", function (e) {
    if (e.key !== "/" || e.ctrlKey || e.metaKey || e.altKey) return;
    var t = e.target;
    if (t && (t.tagName === "INPUT" || t.tagName === "TEXTAREA" || t.isContentEditable)) return;
    e.preventDefault();
    input.focus();
  });

  var heads = Array.prototype.slice.call(document.querySelectorAll("th[data-key]"));
  var sort = { key: "name", dir: 1 };

  function compare(a, b) {
    if (a.dir !== b.dir) return a.dir ? -1 : 1;
    var c = 0;
    if (sort.key === "size" && !a.dir) c = a.size - b.size;
    else if (sort.key === "mtime") c = a.mtime - b.mtime;
    if (c === 0) c = a.name < b.name ? -1 : a.name > b.name ? 1 : 0;
    return c * sort.dir;
  }

  function applySort() {
    var sorted = meta.slice().sort(compare);
    for (var i = 0; i < sorted.length; i++) body.insertBefore(sorted[i].row, none);
    heads.forEach(function (th) {
      if (th.dataset.key === sort.key) {
        th.setAttribute("aria-sort", sort.dir === 1 ? "ascending" : "descending");
      } else {
        th.removeAttribute("aria-sort");
      }
    });
  }

  heads.forEach(function (th) {
    th.querySelector("button").addEventListener("click", function () {
      var key = th.dataset.key;
      if (sort.key === key) sort.dir = -sort.dir;
      else sort = { key: key, dir: key === "name" ? 1 : -1 };
      applySort();
    });
  });

  var drop = document.getElementById("drop");
  if (!drop) return;

  var base = drop.dataset.base;
  var picker = document.getElementById("picker");
  var list = document.getElementById("uploads");
  var live = document.getElementById("upload-status");
  var items = [];
  var running = false;
  var attention = false;

  function reason(status) {
    if (status === 409) return "Already exists";
    if (status === 413) return "Too large";
    if (status === 401) return "Sign in required";
    if (status === 403) return "Not allowed";
    if (status === 411 || status === 400) return "Rejected";
    return "Failed (" + status + ")";
  }

  function show(item, cls, text, retry) {
    var idle = cls !== "queued" && cls !== "sending";
    item.li.className = cls;
    item.state.textContent = text;
    item.cancel.hidden = idle;
    item.retry.hidden = !retry;
    if (idle) live.textContent = item.file.name + ": " + text;
  }

  function settle(item, cls, text, retry) {
    if (item.settled) return false;
    item.settled = true;
    if (cls !== "done") attention = true;
    show(item, cls, text, retry);
    return true;
  }

  function advance(item) {
    if (item.advanced) return;
    item.advanced = true;
    next();
  }

  function target(item) {
    return base + encodeURIComponent(item.file.name);
  }

  // A dropped connection or a late cancel leaves the outcome unknown, so ask the
  // server rather than guess. An existing file is never reported as our upload.
  function reconcile(item, cls, text) {
    var unknown = "Unknown outcome, check the folder";
    fetch(target(item), { method: "HEAD", credentials: "same-origin", cache: "no-store" })
      .then(function (r) {
        if (r.status === 404) return show(item, cls, text, cls === "failed");
        if (!r.ok) return show(item, "uncertain", unknown, false);
        if (r.headers.get("Upload-Complete") !== "?1") {
          return show(item, "uncertain", "Partial upload left on the server", false);
        }
        var same = Number(r.headers.get("Upload-Offset")) === item.file.size;
        show(
          item,
          "uncertain",
          same
            ? "A file of this size is already on the server, not confirmed as yours"
            : "A different file with this name is already on the server",
          false
        );
      })
      .catch(function () {
        show(item, "uncertain", unknown, false);
      });
  }

  function send(item) {
    var xhr = new XMLHttpRequest();
    item.xhr = xhr;
    item.sent = false;
    item.settled = false;
    item.advanced = false;
    item.bar.value = 0;
    show(item, "sending", "Sending", false);
    xhr.open("PUT", target(item));
    xhr.upload.onprogress = function (e) {
      if (e.lengthComputable) item.bar.value = e.loaded / e.total;
    };
    xhr.upload.onload = function () {
      item.sent = true;
      if (!item.settled) item.state.textContent = "Waiting for server";
    };
    xhr.onload = function () {
      if (xhr.status === 201) {
        if (settle(item, "done", "Uploaded", false)) item.bar.value = 1;
      } else {
        settle(item, "failed", reason(xhr.status), xhr.status !== 409);
      }
      advance(item);
    };
    xhr.onerror = function () {
      if (settle(item, "failed", "Network error", false)) {
        item.state.textContent = "Network error, checking the server";
        reconcile(item, "failed", "Network error");
      }
      advance(item);
    };
    xhr.onabort = function () {
      if (settle(item, "cancelled", "Cancelled", false) && item.sent) {
        item.state.textContent = "Cancelled, checking the server";
        reconcile(item, "cancelled", "Cancelled");
      }
      advance(item);
    };
    xhr.send(item.file);
  }

  function next() {
    for (var i = 0; i < items.length; i++) {
      if (items[i].li.className === "queued") {
        send(items[i]);
        return;
      }
    }
    running = false;
    var clean = items.every(function (it) {
      return it.li.className === "done";
    });
    if (clean && !attention && items.length > 0) window.location.reload();
  }

  function pump() {
    if (running) return;
    running = true;
    next();
  }

  function makeButton(text, name) {
    var b = document.createElement("button");
    b.type = "button";
    b.className = "link";
    b.textContent = text;
    b.setAttribute("aria-label", text + " " + name);
    return b;
  }

  function add(file) {
    var li = document.createElement("li");
    var name = document.createElement("span");
    var state = document.createElement("span");
    var bar = document.createElement("progress");
    var actions = document.createElement("span");
    var item = {
      file: file,
      li: li,
      state: state,
      bar: bar,
      cancel: makeButton("Cancel", file.name),
      retry: makeButton("Retry", file.name),
      xhr: null,
      sent: false,
      settled: false,
      advanced: false,
    };
    name.textContent = file.name;
    name.className = "name";
    state.className = "state";
    bar.max = 1;
    bar.value = 0;
    bar.setAttribute("aria-label", "Progress for " + file.name);
    actions.className = "actions";
    actions.appendChild(item.cancel);
    actions.appendChild(item.retry);
    li.appendChild(name);
    li.appendChild(state);
    li.appendChild(bar);
    li.appendChild(actions);
    list.appendChild(li);
    items.push(item);
    show(item, "queued", "Queued", false);

    item.cancel.addEventListener("click", function () {
      if (li.className === "queued") {
        settle(item, "cancelled", "Cancelled", false);
        item.advanced = true;
      } else if (li.className === "sending" && item.xhr) {
        item.xhr.abort();
      }
    });
    item.retry.addEventListener("click", function () {
      if (li.className !== "failed") return;
      item.settled = false;
      item.advanced = false;
      show(item, "queued", "Queued", false);
      item.cancel.focus();
      pump();
    });
  }

  function enqueue(files) {
    for (var i = 0; i < files.length; i++) add(files[i]);
    pump();
  }

  document.getElementById("pick").addEventListener("click", function () {
    picker.click();
  });
  picker.addEventListener("change", function () {
    enqueue(picker.files);
    picker.value = "";
  });
  ["dragenter", "dragover"].forEach(function (t) {
    drop.addEventListener(t, function (e) {
      e.preventDefault();
      drop.classList.add("is-over");
    });
  });
  ["dragleave", "drop"].forEach(function (t) {
    drop.addEventListener(t, function (e) {
      e.preventDefault();
      drop.classList.remove("is-over");
    });
  });
  drop.addEventListener("drop", function (e) {
    if (e.dataTransfer && e.dataTransfer.files) enqueue(e.dataTransfer.files);
  });
})();
