// Content script for the good example.
//
// MV3 rules observed here: the script is a packaged file (not a remote URL),
// it does not eval anything, and it talks to the worker with
// chrome.runtime.sendMessage rather than touching extension APIs directly.

function currentSelection() {
  const selection = window.getSelection();
  return selection ? selection.toString().trim().slice(0, 500) : "";
}

function mountBadge() {
  const badge = document.createElement("button");
  badge.type = "button";
  badge.id = "reading-list-notes-badge";
  badge.textContent = "Save to reading list";
  badge.addEventListener("click", () => {
    chrome.runtime.sendMessage({
      type: "save-page",
      url: window.location.href,
      title: document.title,
      note: currentSelection(),
    });
  });
  document.body.appendChild(badge);
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", mountBadge, { once: true });
} else {
  mountBadge();
}
