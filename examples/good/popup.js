// Popup controller for the good example.
//
// MV3 rule: no inline <script> and no onclick="..." attributes -- the
// extension_pages CSP is "script-src 'self'" with no 'unsafe-inline', so both
// would be blocked. Handlers are attached here with addEventListener instead.

const saveButton = document.getElementById("save");
const noteInput = document.getElementById("note");
const status = document.getElementById("status");

function setStatus(text, isError) {
  status.textContent = text;
  status.style.color = isError ? "#b00020" : "#0b6b3a";
}

saveButton.addEventListener("click", async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || !tab.url) {
    setStatus("No active tab to save.", true);
    return;
  }
  const response = await chrome.runtime.sendMessage({
    type: "save-page",
    url: tab.url,
    title: tab.title || tab.url,
    note: noteInput.value.trim(),
  });
  if (response && response.ok) {
    setStatus(`Saved. ${response.count} item(s) in the list.`, false);
  } else {
    setStatus("Could not save the page.", true);
  }
});

document.addEventListener("DOMContentLoaded", () => {
  noteInput.focus();
});
