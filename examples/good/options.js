// Options page for the good example.
//
// MV3 rule: settings live in chrome.storage, and the handler is bound here
// rather than written as an onchange="..." attribute.

const limitInput = document.getElementById("limit");
const status = document.getElementById("status");
const saveButton = document.getElementById("save-options");

async function load() {
  const stored = await chrome.storage.local.get({ maxItems: 500 });
  limitInput.value = String(stored.maxItems);
}

saveButton.addEventListener("click", async () => {
  const maxItems = Number.parseInt(limitInput.value, 10);
  if (!Number.isInteger(maxItems) || maxItems < 1) {
    status.textContent = "Enter a whole number of at least 1.";
    return;
  }
  await chrome.storage.local.set({ maxItems });
  status.textContent = "Saved.";
});

load();
