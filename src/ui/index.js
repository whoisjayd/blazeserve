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
  var queue = [];
  var running = false;
  var done = 0;
  var failed = 0;

  function reason(status) {
    if (status === 409) return "Already exists";
    if (status === 413) return "Too large";
    if (status === 401) return "Sign in required";
    if (status === 403) return "Not allowed";
    if (status === 411 || status === 400) return "Rejected";
    return "Failed (" + status + ")";
  }

  function send(file, finish) {
    var li = document.createElement("li");
    var name = document.createElement("span");
    var state = document.createElement("span");
    var bar = document.createElement("progress");
    name.textContent = file.name;
    state.className = "state";
    state.textContent = "Uploading";
    bar.max = 1;
    bar.value = 0;
    li.appendChild(name);
    li.appendChild(state);
    li.appendChild(bar);
    list.appendChild(li);

    var xhr = new XMLHttpRequest();
    xhr.open("PUT", base + encodeURIComponent(file.name));
    xhr.upload.onprogress = function (e) {
      if (e.lengthComputable) bar.value = e.loaded / e.total;
    };
    xhr.onload = function () {
      if (xhr.status === 201) {
        li.className = "done";
        state.textContent = "Uploaded";
        bar.value = 1;
        done++;
      } else {
        li.className = "failed";
        state.textContent = reason(xhr.status);
        failed++;
      }
      finish();
    };
    xhr.onerror = function () {
      li.className = "failed";
      state.textContent = "Network error";
      failed++;
      finish();
    };
    xhr.send(file);
  }

  function next() {
    var file = queue.shift();
    if (!file) {
      running = false;
      if (failed === 0 && done > 0) window.location.reload();
      return;
    }
    send(file, next);
  }

  function enqueue(files) {
    for (var i = 0; i < files.length; i++) queue.push(files[i]);
    if (!running && queue.length > 0) {
      running = true;
      done = 0;
      failed = 0;
      next();
    }
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
