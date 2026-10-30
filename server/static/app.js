// Small progressive enhancements for the setec web UI. These live in a
// static file because the server's Content-Security-Policy forbids inline
// scripts.
"use strict";

document.addEventListener("click", (e) => {
  // Close any open "…" menu when clicking outside it, or on one of its items.
  for (const menu of document.querySelectorAll("details.menu[open]")) {
    if (!menu.contains(e.target) || e.target.closest(".menu-items")) {
      menu.open = false;
    }
  }

  const copy = e.target.closest("[data-copy]");
  if (copy) {
    const label = copy.lastChild;
    const orig = label.textContent;
    navigator.clipboard.writeText(copy.dataset.copy).then(
      () => flashLabel(label, "Copied!", orig),
      () => flashLabel(label, "Copy failed", orig),
    );
    return;
  }
  const toggle = e.target.closest("[data-toggle]");
  if (toggle) {
    const el = document.querySelector(toggle.dataset.toggle);
    el.hidden = !el.hidden;
    if (!el.hidden) {
      el.scrollIntoView({ behavior: "smooth", block: "nearest" });
      el.querySelector("input:not([type=hidden]), textarea")?.focus({ preventScroll: true });
    }
    return;
  }
  const dismiss = e.target.closest("[data-dismiss]");
  if (dismiss) dismiss.closest(".toast").remove();
});

function flashLabel(node, text, orig) {
  node.textContent = text;
  setTimeout(() => (node.textContent = orig), 1500);
}

// Close open menus on Escape.
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") {
    for (const menu of document.querySelectorAll("details.menu[open]")) menu.open = false;
  }
});

// Success toasts dismiss themselves; errors stay until closed.
document.addEventListener("htmx:afterSettle", () => {
  for (const toast of document.querySelectorAll(".toast[data-autodismiss]")) {
    toast.removeAttribute("data-autodismiss");
    setTimeout(() => toast.remove(), 4000);
  }
});

// Client-side filtering of the secrets list. This is done in the browser
// rather than on the server so that typing does not spam the audit log.
document.addEventListener("input", (e) => {
  const input = e.target.closest("[data-filter]");
  if (!input) return;
  const q = input.value.trim().toLowerCase();
  const table = document.querySelector(input.dataset.filter);
  if (!table) return;
  let shown = 0;
  for (const row of table.tBodies[0].rows) {
    const match = row.dataset.name.toLowerCase().includes(q);
    row.hidden = !match;
    if (match) shown++;
  }
  document.querySelector("[data-count]").textContent = shown;
  document.querySelector("[data-empty]").hidden = shown > 0;
});

// Destructive forms keep their submit button disabled until the user types
// the expected confirmation text. The server checks it as well.
document.addEventListener("input", (e) => {
  const input = e.target.closest("[data-must-match]");
  if (!input) return;
  input.form.querySelector("button[type=submit]").disabled =
    input.value !== input.dataset.mustMatch;
});

// "/" focuses the search box, as in the Tailscale console.
document.addEventListener("keydown", (e) => {
  if (e.key !== "/" || e.target.closest("input, textarea")) return;
  const input = document.querySelector("[data-filter]");
  if (input) {
    e.preventDefault();
    input.focus();
  }
});
