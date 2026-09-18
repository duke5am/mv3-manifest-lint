// Service worker for the good example.
//
// MV3 rule: the worker is event-driven. There is no page lifetime to lean on,
// so state lives in chrome.storage rather than in a module-level variable.

const STORAGE_KEY = "readingList";

async function readList() {
  const stored = await chrome.storage.local.get(STORAGE_KEY);
  return Array.isArray(stored[STORAGE_KEY]) ? stored[STORAGE_KEY] : [];
}

async function saveEntry(entry) {
  const list = await readList();
  list.push(entry);
  await chrome.storage.local.set({ [STORAGE_KEY]: list });
  return list.length;
}

chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.set({ installedAt: new Date().toISOString() });
});

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (!message || message.type !== "save-page") {
    return false;
  }
  saveEntry({
    url: message.url,
    title: message.title,
    note: message.note,
    savedAt: new Date().toISOString(),
  })
    .then((count) => sendResponse({ ok: true, count }))
    .catch((error) => sendResponse({ ok: false, error: String(error) }));
  return true; // keep the message channel open for the async response
});

// The toolbar click is handled by the popup when one is configured, so this
// listener only fires when no default_popup is set.
chrome.action.onClicked.addListener(async (tab) => {
  if (!tab.url) {
    return;
  }
  await saveEntry({ url: tab.url, title: tab.title || tab.url, note: "" });
});
