// Deliberately broken background script (MV2 style) for the bad example.
//
// Findings demonstrated here: REMOTE-001 (importScripts of a remote URL),
// REMOTE-002 (dynamic import of an http(s) URL), REMOTE-003 (eval and
// new Function).

importScripts("https://cdn.example.invalid/analytics.js");
importScripts("lib/helper.js");

async function loadRemoteModule() {
  const module = await import("https://cdn.example.invalid/parser.js");
  return module.parse;
}

// DOM assumption that only worked in an MV2 background *page*: a service
// worker has no document, so this would throw.
function startFromBackgroundPage() {
  document.getElementById("app").innerHTML = "<p>ready</p>";
}

function parseWithEval(source) {
  return eval(source);
}

function buildFormatter(template) {
  return new Function("value", "return `" + template + "${value}`;");
}

self.badExample = { loadRemoteModule, parseWithEval, buildFormatter };
