// aertun admin: the one script.
//
// Everything here is an addition. Every screen works with it switched off,
// because a browser that blocks it, a policy that forbids it, or a person who
// disabled scripts should lose speed, not features.
//
// It does these things:
//
//   * a command palette, opened with Ctrl+K (⌘K on a Mac) or the button in
//     the search box, which jumps to any screen in the navigation by typing
//     part of its name, and offers to search for anything else;
//   * "/" moves to the search box, as it does on most sites people use;
//   * the menu control collapses the menu to a rail and back at once,
//     rather than by loading the page again. The form it submits is the
//     same one, so the choice is kept the same way, and without the script
//     it still works;
//   * on the rail, pointing at a section opens its flyout after a moment
//     and moving away closes it, as Gmail's does. Clicking, Enter and
//     Escape work without the script; this only adds the pointer;
//   * a menu longer than the window opens scrolled to the current screen;
//   * on a phone, a table of four columns or more reads as a stack of cards,
//     each value under its column's name, instead of hiding the columns
//     that matter past the edge of the screen. Without the script the table
//     scrolls sideways, with a shadow at the edge that says it does;
//   * on a run's page taken over, a click on the live picture presses there;
//   * on Today and the Agents board, a live stream of what the audit log
//     records as it happens (server-sent events from /live), which moves
//     the counts on the page and speaks when something waits for a person.
//     If the stream cannot be held, the page says so and falls back to
//     reloading once a minute — it never pretends to be live.
//
// The palette is a native <dialog> with the ARIA combobox pattern: the
// input owns a listbox, arrow keys move the active option, Enter opens it,
// Escape closes. It reads the destinations from the navigation already on
// the page, so it can never offer a screen this person may not open.
(function () {
  "use strict";

  var mac = /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent);

  function destinations() {
    var out = [];
    document.querySelectorAll(".navgroup").forEach(function (group) {
      var heading = group.querySelector("summary h2");
      var section = heading ? heading.textContent.trim() : "";
      group.querySelectorAll(".nav a[href]").forEach(function (a) {
        out.push({ label: a.textContent.trim(), section: section, href: a.getAttribute("href") });
      });
    });
    return out;
  }

  // Letters in order, not necessarily together: "fw" finds Frameworks.
  // A match at the start of a word ranks first, then a match anywhere.
  function score(label, query) {
    var l = label.toLowerCase(), q = query.toLowerCase().trim();
    if (!q) return 1;
    if (l.indexOf(q) === 0) return 4;
    if (l.indexOf(" " + q) >= 0) return 3;
    if (l.indexOf(q) >= 0) return 2;
    var i = 0;
    for (var c = 0; c < l.length && i < q.length; c++) {
      if (l[c] === q[i]) i++;
    }
    return i === q.length ? 1 : 0;
  }

  var dialog, input, list, items = [], active = -1;

  function build() {
    dialog = document.createElement("dialog");
    dialog.className = "palette";
    dialog.setAttribute("aria-label", "Go to a screen");

    var label = document.createElement("label");
    label.className = "visually-hidden";
    label.htmlFor = "palette-input";
    label.textContent = "Go to a screen, or search";

    input = document.createElement("input");
    input.id = "palette-input";
    input.type = "text";
    input.autocomplete = "off";
    input.spellcheck = false;
    input.placeholder = "Go to a screen, or search…";
    input.setAttribute("role", "combobox");
    input.setAttribute("aria-expanded", "true");
    input.setAttribute("aria-controls", "palette-list");
    input.setAttribute("aria-autocomplete", "list");

    list = document.createElement("ul");
    list.id = "palette-list";
    list.setAttribute("role", "listbox");
    list.setAttribute("aria-label", "Screens");

    var hint = document.createElement("p");
    hint.className = "palette-hint";
    hint.textContent = "↑ ↓ to move · Enter to open · Esc to close";

    dialog.appendChild(label);
    dialog.appendChild(input);
    dialog.appendChild(list);
    dialog.appendChild(hint);
    document.body.appendChild(dialog);

    input.addEventListener("input", render);
    input.addEventListener("keydown", keys);
    list.addEventListener("click", function (e) {
      var li = e.target.closest("li[role=option]");
      if (li) go(Number(li.dataset.index));
    });
    dialog.addEventListener("click", function (e) {
      if (e.target === dialog) dialog.close();
    });
  }

  function render() {
    var q = input.value;
    var all = destinations().map(function (d) {
      return { d: d, s: Math.max(score(d.label, q), score(d.section, q) > 2 ? 1 : 0) };
    }).filter(function (x) { return x.s > 0; });
    all.sort(function (a, b) { return b.s - a.s; });
    items = all.slice(0, 12).map(function (x) { return x.d; });
    if (q.trim()) {
      items.push({ label: "Search for “" + q.trim() + "”", section: "Search",
                   href: "/find?q=" + encodeURIComponent(q.trim()) });
    }
    list.textContent = "";
    items.forEach(function (d, i) {
      var li = document.createElement("li");
      li.id = "palette-opt-" + i;
      li.setAttribute("role", "option");
      li.dataset.index = String(i);
      var name = document.createElement("span");
      name.className = "palette-name";
      name.textContent = d.label;
      var where = document.createElement("span");
      where.className = "palette-where";
      where.textContent = d.section;
      li.appendChild(name);
      li.appendChild(where);
      list.appendChild(li);
    });
    move(items.length ? 0 : -1);
  }

  function move(i) {
    active = i;
    list.querySelectorAll("[role=option]").forEach(function (li, n) {
      li.setAttribute("aria-selected", n === i ? "true" : "false");
      if (n === i) li.scrollIntoView({ block: "nearest" });
    });
    if (i >= 0) input.setAttribute("aria-activedescendant", "palette-opt-" + i);
    else input.removeAttribute("aria-activedescendant");
  }

  function keys(e) {
    if (e.key === "ArrowDown") { e.preventDefault(); move(Math.min(active + 1, items.length - 1)); }
    else if (e.key === "ArrowUp") { e.preventDefault(); move(Math.max(active - 1, 0)); }
    else if (e.key === "Enter" && active >= 0) { e.preventDefault(); go(active); }
  }

  function go(i) {
    var d = items[i];
    if (!d) return;
    // Closed first: a page left with a modal dialog open makes the
    // cross-fade between pages give up, with an error in the console.
    dialog.close();
    window.location.assign(d.href);
  }

  function open() {
    if (!dialog) build();
    input.value = "";
    render();
    dialog.showModal();
    input.focus();
  }

  document.addEventListener("keydown", function (e) {
    var typing = /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement.tagName) ||
      document.activeElement.isContentEditable;
    if ((e.ctrlKey || e.metaKey) && !e.altKey && e.key.toLowerCase() === "k") {
      e.preventDefault();
      open();
    } else if (e.key === "/" && !typing && !e.ctrlKey && !e.metaKey) {
      var find = document.getElementById("findq");
      if (find) { e.preventDefault(); find.focus(); }
    }
  });

  document.querySelectorAll("form.navtoggle").forEach(function (form) {
    form.addEventListener("submit", function (e) {
      if (!window.fetch) return;
      e.preventDefault();
      var to = form.elements.to, button = form.querySelector("button");
      var hide = to.value === "hidden";
      var menu = document.getElementById("sitenav");
      if (menu && menu.matches && menu.matches(":popover-open")) menu.hidePopover();
      fetch(form.action, { method: "POST", body: new URLSearchParams(new FormData(form)),
        credentials: "same-origin", redirect: "manual" }).then(function (r) {
        if (r.type !== "opaqueredirect" && !r.ok) throw new Error(String(r.status));
        document.body.classList.toggle("nav-hidden", hide);
        to.value = hide ? "shown" : "hidden";
        button.setAttribute("aria-expanded", hide ? "false" : "true");
        var tip = (hide ? "Expand" : "Collapse") + " the menu";
        if (button.dataset.tip) button.dataset.tip = tip; else button.title = tip;
      }).catch(function () { form.submit(); });
    });
  });

  // The rail opens the menu beside the button that was used, with that
  // section open and the others closed, so the panel is that section.
  var menu = document.getElementById("sitenav"), from = null;
  function place(btn) {
    var r = menu.getBoundingClientRect(), b = btn.getBoundingClientRect();
    if (Math.abs(r.left - (b.right + 4)) <= 2 && r.top >= 0 && r.bottom <= innerHeight) return;
    menu.style.positionArea = "none";
    menu.style.left = (b.right + 4) + "px";
    menu.style.top = Math.max(8, Math.min(b.top, innerHeight - r.height - 8)) + "px";
  }
  function section(btn) {
    from = btn;
    document.querySelectorAll(".railitem.open").forEach(function (o) { o.classList.remove("open"); });
    btn.classList.add("open");
    menu.querySelectorAll(".navgroup").forEach(function (g) {
      g.open = g.getAttribute("data-section") === btn.getAttribute("data-section");
      // Its heading is a heading here, not a control that would empty the panel.
      g.querySelector("summary").tabIndex = -1;
    });
    menu.classList.add("one-section");
  }
  // While it is one section, its heading does not fold it away.
  if (menu) menu.addEventListener("click", function (e) {
    if (menu.classList.contains("one-section") && e.target.closest("summary")) e.preventDefault();
  });
  if (menu && menu.showPopover) {
    var opening, closing;
    var hovering = function (e) { return e.pointerType === "mouse" && document.body.classList.contains("nav-hidden"); };
    document.querySelectorAll(".railitem").forEach(function (btn) {
      btn.addEventListener("click", function () { section(btn); });
      btn.addEventListener("pointerenter", function (e) {
        if (!hovering(e)) return;
        clearTimeout(closing);
        opening = setTimeout(function () {
          section(btn);
          if (menu.matches(":popover-open")) { menu.style.left = menu.style.top = ""; menu.style.positionArea = ""; menu.hidePopover(); }
          menu.showPopover({ source: btn });
        }, 150);
      });
      btn.addEventListener("pointerleave", function (e) { if (hovering(e)) leave(); });
    });
    menu.addEventListener("pointerenter", function () { clearTimeout(closing); });
    menu.addEventListener("pointerleave", function (e) { if (hovering(e)) leave(); });
    function leave() {
      clearTimeout(opening);
      closing = setTimeout(function () {
        if (menu.matches(":popover-open") && !menu.contains(document.activeElement)) menu.hidePopover();
      }, 300);
    }
    menu.addEventListener("toggle", function (e) {
      if (e.newState === "open" && from && document.body.classList.contains("nav-hidden")) place(from);
      if (e.newState === "closed") {
        menu.style.left = menu.style.top = ""; menu.style.positionArea = "";
        menu.classList.remove("one-section");
        menu.querySelectorAll(".navgroup > summary").forEach(function (s) { s.removeAttribute("tabindex"); });
        document.querySelectorAll(".railitem.open").forEach(function (o) { o.classList.remove("open"); });
      }
    });
  }

  // Plain tooltips, as Material draws them: a control's title shown after
  // a moment of pointing, or at once on keyboard focus, below it (above
  // when there is no room), gone on leaving or Escape. Taken from the
  // title so the browser's own does not appear as well; screen readers
  // already hear each control's name, so the tooltip is hidden from them.
  var tooltip = null, tipping;
  function tipShow(el) {
    if (!tooltip) {
      tooltip = document.createElement("div");
      tooltip.className = "tooltip";
      tooltip.setAttribute("popover", "manual");
      tooltip.setAttribute("aria-hidden", "true");
      document.body.appendChild(tooltip);
    }
    if (!tooltip.showPopover) return;
    tooltip.textContent = el.dataset.tip;
    if (!tooltip.matches(":popover-open")) tooltip.showPopover();
    var r = el.getBoundingClientRect(), t = tooltip.getBoundingClientRect();
    var left = Math.max(8, Math.min(r.left + r.width / 2 - t.width / 2, innerWidth - t.width - 8));
    var top = r.bottom + 4;
    if (top + t.height > innerHeight - 8) top = r.top - t.height - 4;
    tooltip.style.left = left + "px";
    tooltip.style.top = top + "px";
  }
  function tipHide() {
    clearTimeout(tipping);
    if (tooltip && tooltip.matches(":popover-open")) tooltip.hidePopover();
  }
  // Signing out a session nobody is using (session.idle). The server
  // decides; the page tells it somebody is here — a key, a click, a
  // scroll — at most every half minute, warns a minute before the end so
  // a person who is reading can stay, and afterwards offers to sign in
  // again with their passkey without leaving the page, so nothing on it
  // is lost. Only the person the page was theirs carries on with it.
  (function () {
    var meta = document.querySelector('meta[name="aertun-idle"]');
    var idle = meta ? parseInt(meta.content, 10) * 1000 : 0;
    if (!(idle > 0)) return;
    var whoMeta = document.querySelector('meta[name="aertun-who"]');
    var who = whoMeta ? whoMeta.content : "";
    var told = Date.now(), used = told, warning = null, ended = false;
    function close() {
      if (warning) { warning.close(); warning.remove(); warning = null; }
    }
    function tell() {
      if (ended) return;
      told = Date.now();
      fetch("/session/alive", { method: "POST", credentials: "same-origin", cache: "no-store" })
        .then(function (r) { if (r.status === 401) signedOut(); }, function () {});
      close();
    }
    function bytes(s) {
      s = s.replace(/-/g, "+").replace(/_/g, "/");
      while (s.length % 4) { s += "="; }
      var raw = atob(s), out = new Uint8Array(raw.length);
      for (var i = 0; i < raw.length; i++) { out[i] = raw.charCodeAt(i); }
      return out;
    }
    function text(buffer) {
      var b = new Uint8Array(buffer), s = "";
      for (var i = 0; i < b.length; i++) { s += String.fromCharCode(b[i]); }
      return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    }
    function post(url, body) {
      return fetch(url, { method: "POST", credentials: "same-origin", cache: "no-store",
        headers: { "Content-Type": "application/json" }, body: JSON.stringify(body || {}) })
        .then(function (r) {
          return r.json().then(function (d) {
            if (!r.ok) { throw new Error(d.error || "that did not work"); }
            return d;
          });
        });
    }
    // The session has ended: say so, and offer the passkey, in place.
    function signedOut() {
      if (ended) return;
      ended = true;
      close();
      warning = document.createElement("dialog");
      warning.className = "idle-warn";
      warning.setAttribute("aria-labelledby", "idle-warn-title");
      var h = document.createElement("h2");
      h.id = "idle-warn-title";
      h.textContent = "Signed out";
      var p = document.createElement("p");
      p.textContent = "Nobody used the admin for " + Math.round(idle / 60000) + " minutes, so you were signed out, " +
        "as your organisation requires. Sign in again with your passkey to carry on here: nothing on this page is lost.";
      var said = document.createElement("p");
      said.setAttribute("role", "status");
      var again = document.createElement("button");
      again.type = "button";
      again.textContent = "Use my passkey";
      var other = document.createElement("a");
      other.href = "/signin?e=idle";
      other.className = "btn-text";
      other.textContent = "Sign in another way";
      again.addEventListener("click", function () {
        again.disabled = true;
        said.textContent = "Waiting for your device…";
        var challenge = null;
        post("/signin/passkey/challenge").then(function (start) {
          challenge = start.challenge;
          return navigator.credentials.get({ publicKey: { challenge: bytes(start.challenge),
            rpId: start.rpId, userVerification: "required", timeout: 120000 } });
        }).then(function (c) {
          if (!c) { throw new Error("no passkey was offered"); }
          return post("/signin/passkey/verify", { id: c.id, challenge: challenge, expect: who,
            clientDataJSON: text(c.response.clientDataJSON),
            authenticatorData: text(c.response.authenticatorData),
            signature: text(c.response.signature) });
        }).then(function (done) {
          // A sign-in held back for its person to confirm goes there.
          if (done.next && done.next.indexOf("/signin/verify") === 0) { location.href = done.next; return; }
          ended = false;
          told = used = Date.now();
          if (!done.notice) { close(); return; }
          said.textContent = done.notice;
          again.textContent = "Carry on";
          again.disabled = false;
          again.onclick = close;
          other.remove();
        }).catch(function (err) {
          again.disabled = false;
          said.textContent = err && err.message ? err.message : "that did not work";
        });
      });
      // Not dismissed by Escape: behind it is a page that can no longer
      // save, and the two ways out are the ones offered.
      warning.addEventListener("cancel", function (e) { e.preventDefault(); });
      warning.append(h, p, said);
      if (window.PublicKeyCredential) { warning.append(again); }
      warning.append(other);
      document.body.append(warning);
      warning.showModal();
      (window.PublicKeyCredential ? again : other).focus();
    }
    function use() {
      used = Date.now();
      if (used - told > 30000) tell();
    }
    ["keydown", "pointerdown", "wheel", "touchstart", "input"].forEach(function (ev) {
      document.addEventListener(ev, use, { passive: true, capture: true });
    });
    function warn() {
      warning = document.createElement("dialog");
      warning.className = "idle-warn";
      warning.setAttribute("aria-labelledby", "idle-warn-title");
      var h = document.createElement("h2");
      h.id = "idle-warn-title";
      h.textContent = "Still there?";
      var p = document.createElement("p");
      p.textContent = "Nobody has used the admin for a while, so in a minute you will be signed out, as your organisation requires.";
      var stay = document.createElement("button");
      stay.type = "button";
      stay.textContent = "Stay signed in";
      stay.addEventListener("click", tell);
      warning.append(h, p, stay);
      document.body.append(warning);
      warning.showModal();
      stay.focus();
    }
    setInterval(function () {
      if (ended) return;
      var now = Date.now(), left = idle - (now - told);
      // Use the throttle held back is told before it could matter.
      if (used > told && (now - told > 30000 || left <= 60000)) { tell(); return; }
      // Past the end, and a moment more, the server signs the session out
      // on the next request, which this makes, and the page offers to
      // sign in again where it is.
      if (left <= -2000) {
        fetch("/session/alive", { method: "POST", credentials: "same-origin", cache: "no-store" })
          .then(function (r) { if (r.status === 401) { signedOut(); } else { told = Date.now(); } },
            function () {});
        return;
      }
      if (left <= 60000 && !warning) warn();
    }, 5000);
  })();

  // Copy buttons: hidden until the clipboard can be written (it needs a
  // secure context), so without it the text is still there to select.
  document.querySelectorAll("button[data-copy]").forEach(function (btn) {
    var src = document.getElementById(btn.getAttribute("data-copy"));
    var said = document.getElementById(btn.getAttribute("data-copied") || "");
    if (!src || !navigator.clipboard || !window.isSecureContext) return;
    btn.hidden = false;
    btn.addEventListener("click", function () {
      navigator.clipboard.writeText(src.value || src.textContent).then(function () {
        if (said) said.textContent = "Copied.";
      }, function () {
        if (said) said.textContent = "Could not copy; select the text instead.";
      });
    });
  });

  // An identifier too long for its column, and a status too long for the
  // screen, end in an ellipsis (style.css, "no word broken in two"). The
  // whole of it is shown on pointing, and on focus, so it can be read
  // without being selected.
  var clipped = "td code, th code, .tag, .pill, .chip, .chip-small, .wf-band, .wf-word, .wf-tag, .wf-task";
  document.querySelectorAll(clipped).forEach(function (c) {
    if (c.scrollWidth > c.clientWidth + 1 && !c.title) {
      c.title = c.textContent;
      c.tabIndex = 0;
    }
  });

  document.querySelectorAll("header.bar [title], .iconbutton[title], .rowmenu-open[title], svg [data-tip], [tabindex][title]").forEach(function (el) {
    if (el.hasAttribute("title")) {
      el.dataset.tip = el.getAttribute("title");
      el.removeAttribute("title");
    }
    el.addEventListener("pointerenter", function (e) {
      if (e.pointerType !== "mouse") return;
      clearTimeout(tipping);
      tipping = setTimeout(function () { tipShow(el); }, 500);
    });
    el.addEventListener("pointerleave", tipHide);
    el.addEventListener("focus", function () { if (el.matches(":focus-visible")) tipShow(el); });
    el.addEventListener("blur", tipHide);
    el.addEventListener("click", tipHide);
  });
  document.addEventListener("keydown", function (e) { if (e.key === "Escape") tipHide(); });

  // The current screen's item, in view. A menu longer than the window
  // scrolls inside itself, and a screen low in it — Automations, Sign-ins —
  // opened with its own item below the fold. Only the menu moves, never the
  // page, and only when the item is not already showing.
  var navbox = document.querySelector(".sidenav > .navgroups");
  var here = navbox && navbox.querySelector('a[aria-current="page"]');
  if (here && navbox.scrollHeight > navbox.clientHeight) {
    var nb = navbox.getBoundingClientRect(), hb = here.getBoundingClientRect();
    if (hb.bottom > nb.bottom || hb.top < nb.top) {
      navbox.scrollTop += hb.top - nb.top - (nb.height - hb.height) / 2;
    }
  }

  // Tables that become cards on a phone (style.css, table.stacks): each
  // cell is labelled with its column's heading, spans included, so a
  // value never appears without the name of what it is. A table can opt
  // out with data-nostack; one with fewer than four columns needs no help.
  document.querySelectorAll(".table-wrap table").forEach(function (t) {
    if (t.hasAttribute("data-nostack") || !t.tHead) return;
    var row = t.tHead.rows[t.tHead.rows.length - 1];
    if (!row || row.cells.length < 4) return;
    var names = [];
    Array.prototype.forEach.call(row.cells, function (c) {
      var name = c.textContent.trim();
      for (var i = 0; i < (c.colSpan || 1); i++) names.push(name);
    });
    Array.prototype.forEach.call(t.tBodies, function (body) {
      Array.prototype.forEach.call(body.rows, function (tr) {
        var at = 0;
        Array.prototype.forEach.call(tr.cells, function (cell) {
          var name = names[at] || "";
          if (name && cell.tagName === "TD" && !cell.hasAttribute("data-label")) cell.setAttribute("data-label", name);
          at += cell.colSpan || 1;
        });
      });
    });
    t.classList.add("stacks");
  });

  // A run's page taken over (agent_run.html): a click on the live picture
  // presses there, in the picture's own pixels, which are the page's; text
  // and keys are posted without leaving the page, and the picture follows.
  // Without this, text and keys are posted by the form and the page comes
  // back; only pressing a point needs it.
  document.querySelectorAll(".takeover").forEach(function (box) {
    var page = box.querySelector("img.takeover-page");
    var form = box.querySelector("form.takeover-form");
    if (!page || !form) return;
    page.setAttribute("data-live", "");
    var hint = box.querySelector("[data-takeover-hint]");
    if (hint) hint.hidden = false;
    function send(body) {
      fetch(form.action, {method: "POST", body: new URLSearchParams(body), credentials: "same-origin"})
        .then(function () {
          setTimeout(function () {
            page.src = page.src.split("?")[0] + "?t=" + Date.now();
          }, 400);
        });
    }
    page.addEventListener("click", function (e) {
      var r = page.getBoundingClientRect();
      if (!r.width || !r.height || !page.naturalWidth) return;
      var b = new FormData(form);
      b.delete("text");
      b.set("x", Math.round((e.clientX - r.left) / r.width * page.naturalWidth));
      b.set("y", Math.round((e.clientY - r.top) / r.height * page.naturalHeight));
      send(b);
    });
    form.addEventListener("submit", function (e) {
      e.preventDefault();
      var b = new FormData(form);
      if (e.submitter && e.submitter.name) b.set(e.submitter.name, e.submitter.value);
      send(b);
      var t = form.querySelector('input[name="text"]');
      if (t) t.value = "";
    });
  });

  // The live stream (Today and the Agents board, where the badge is).
  // Server-sent events over the audit log: the stream carries ids, kinds,
  // states and counters and nothing else (live.go holds itself to that),
  // and every word shown to a person is written here — the stream cannot
  // put a sentence on the page any more than a log entry can.
  //
  // Everything it moves already works without it: the counts are rendered
  // by the server, the Refresh form reloads the page, and the badge stays
  // silent rather than claiming something it is not doing.
  (function () {
    var badge = document.querySelector("[data-live-badge]");
    if (!badge) return; // a screen without a badge has no stream to follow
    var reduce = window.matchMedia
      ? window.matchMedia("(prefers-reduced-motion: reduce)").matches : false;

    // The states that take a finding out of the triage queue, and the run
    // states that count as an automation having acted. Closed sets, kept in
    // step with the server's by hand: an unknown word from the stream is
    // ignored rather than guessed at.
    var closing = { fixed: true, stale: true, "false-positive": true, benign: true };
    var ranStates = { done: true, watched: true, limited: true };

    function cookieNamed(name) {
      var parts = document.cookie ? document.cookie.split(";") : [];
      for (var i = 0; i < parts.length; i++) {
        var bit = parts[i].trim();
        if (bit.indexOf(name + "=") === 0) return bit.slice(name.length + 1);
      }
      return "";
    }

    // Move a figure the stream says moved. Clamped at zero: the deltas are
    // a hint beside the truth, and a count of minus one on a page that
    // started at zero is a lie with a number in it. The tile links to the
    // records, which remain the count that is real.
    function bump(href, by) {
      var tile = document.querySelector('[data-live-count="' + href + '"]');
      var dd = tile && tile.querySelector("dd a");
      if (!dd) return;
      var n = (parseInt(dd.textContent, 10) || 0) + by;
      dd.textContent = String(Math.max(0, n));
    }

    function waiting(by) {
      var h = document.querySelector('[data-live="waiting"]');
      if (!h) return;
      var span = h.querySelector(".count");
      var n = (span ? parseInt(span.textContent, 10) || 0 : 0) + by;
      if (!span) {
        if (n <= 0) return; // nothing was shown; a removal changes nothing
        span = document.createElement("span");
        span.className = "count";
        h.appendChild(span);
      }
      span.textContent = String(Math.max(0, n));
      // The empty state stops being true the moment something waits.
      var empty = document.querySelector('[data-live="waiting-empty"]');
      if (empty && n > 0) {
        empty.textContent = "";
        var open = document.createElement("a");
        open.href = "/approvals";
        open.textContent = "Something is waiting for you.";
        empty.appendChild(open);
      }
    }

    // The snackbar: one at a time, announced without taking focus, gone on
    // its own. Drawn with the stylesheet's snackbar component tokens
    // through the style object, because the content security policy allows
    // no style attributes and the palette of this interface lives in one
    // place. A popover in the manual state so nothing on the page has to be
    // stacked under it; the fade, when motion is welcome, runs on the
    // motion tokens the stylesheet zeroes under prefers-reduced-motion —
    // and the check above skips it there regardless, because a kill switch
    // that depends on a variable resolving is not a kill switch.
    var snack = null, away = null;
    function say(what, href) {
      if (snack) snack.remove();
      clearTimeout(away);
      snack = document.createElement("div");
      snack.setAttribute("role", "status");
      snack.setAttribute("popover", "manual");
      var s = snack.style;
      s.setProperty("position", "fixed");
      s.setProperty("left", "50%");
      s.setProperty("bottom", "1.5rem");
      s.setProperty("transform", "translateX(-50%)");
      s.setProperty("max-width", "min(32rem, calc(100vw - 2rem))");
      s.setProperty("display", "flex");
      s.setProperty("align-items", "baseline");
      s.setProperty("gap", "1rem");
      s.setProperty("padding", "0.75rem 1.25rem");
      s.setProperty("background", "var(--md-comp-snackbar-container-color)");
      s.setProperty("color", "var(--md-comp-snackbar-supporting-text-color)");
      s.setProperty("border-radius", "var(--md-comp-snackbar-container-shape)");
      s.setProperty("box-shadow", "var(--md-comp-snackbar-elevation)");
      s.setProperty("border", "none");
      if (!reduce) s.setProperty("transition",
        "opacity var(--motion-default-effects-duration) var(--spring-effects)");
      var text = document.createElement("span");
      text.textContent = what;
      snack.appendChild(text);
      if (href) {
        var open = document.createElement("a");
        open.href = href;
        open.textContent = "Open";
        open.style.setProperty("color", "var(--md-comp-snackbar-action-label-color)");
        snack.appendChild(open);
      }
      document.body.appendChild(snack);
      if (snack.showPopover) snack.showPopover();
      away = setTimeout(function () {
        if (snack) snack.remove();
        snack = null;
      }, 6000);
    }

    if (!window.EventSource) return; // the Refresh form is the fallback, and it is already there

    var waitingWords = {
      act: "An act on another platform is waiting for you",
      automation: "An automation is held for your approval",
      change: "A change needs a second administrator"
    };

    function data(e) {
      try { return JSON.parse(e.data); } catch (x) { return null; }
    }

    var es = null, fails = 0, polled = cookieNamed("aertun_poll") !== "";

    // The fallback, used once: after three failures the page stops
    // pretending and reloads itself once a minute instead, visibly. Not
    // while already in that mode — the reload is coming on its own minute,
    // and re-marking it here would reload every few seconds forever, which
    // is a page that cannot be read rather than one that is not live.
    function fallback() {
      if (polled) { badge.textContent = "○ every 60s"; return; }
      es.close();
      document.cookie = "aertun_poll=1; path=/; Max-Age=3600; SameSite=Strict";
      location.reload();
    }

    function connect() {
      es = new EventSource("/live");
      es.onopen = function () {
        fails = 0;
        badge.textContent = "● live";
        // Holding the stream again ends poll mode on the next load: the
        // cookie goes now, the reload that follows renders live.
        if (polled) {
          document.cookie = "aertun_poll=; path=/; Max-Age=0; SameSite=Strict";
          polled = false;
        }
      };
      es.onerror = function () {
        fails++;
        if (fails >= 3) { fallback(); return; }
        if (es.readyState === EventSource.CLOSED) {
          // Refused outright — the cap, or a build with nothing to stream.
          // EventSource does not retry a non-200 by itself, so this waits
          // and tries again, one strike at a time, until fallback decides.
          es.close();
          setTimeout(connect, 3000 + fails * 2000);
        } else {
          badge.textContent = "○ reconnecting…";
        }
      };
      es.addEventListener("waiting", function (e) {
        var d = data(e);
        if (!d) return;
        waiting(d.delta);
        if (d.delta > 0 && waitingWords[d.kind]) say(waitingWords[d.kind], "/approvals");
      });
      es.addEventListener("decision", function (e) {
        var d = data(e);
        if (d && closing[d.to]) bump("/findings", -1);
      });
      es.addEventListener("case", function (e) {
        var d = data(e);
        if (!d || !d.id) return;
        if (d.state === "open") {
          bump("/security/cases", 1);
          say("A case was opened", "/security/case/" + encodeURIComponent(d.id));
        } else if (d.state === "closed") {
          bump("/security/cases", -1);
        }
      });
      es.addEventListener("detection", function (e) {
        var d = data(e);
        if (d && d.opened > 0) bump("/findings", d.opened);
      });
      es.addEventListener("agent", function (e) {
        var d = data(e);
        if (d && d.refused) {
          // The Agents board counts refusals; its tile carries the same
          // data-live-count name wherever the page is open, so the figure
          // moves on the board and the sentence goes to whoever is watching.
          bump("/security/agents", 1);
          say("An agent call was refused", "/security/agents");
        }
      });
      es.addEventListener("automation", function (e) {
        var d = data(e);
        if (d && ranStates[d.state]) bump("/security/automations", 1);
      });
      // "proposal" arrives and is not shown: a suggestion is read on the
      // finding it is about, which loads fresh, and a snackbar quoting a
      // verdict nobody made is automation bias with a toast in it.
    }
    connect();
  })();

  // The shortcut, shown where people look for search, in their platform's
  // spelling. Only once the script is running, since it is what makes it work.
  document.querySelectorAll("[data-palette]").forEach(function (b) {
    b.hidden = false;
    var k = b.querySelector("kbd");
    if (k) k.textContent = mac ? "⌘K" : "Ctrl K";
    b.addEventListener("click", open);
  });
})();
