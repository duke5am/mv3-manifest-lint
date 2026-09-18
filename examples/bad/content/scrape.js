// Deliberately broken content script for the bad example.
//
// Findings demonstrated here: REMOTE-003 (eval).

function collectImages() {
  return Array.from(document.images).map(function (image) {
    return image.src;
  });
}

function runRules(rulesAsJson) {
  // Rule sets were shipped as JSON strings in the MV2 version and evaluated.
  var rules = eval("(" + rulesAsJson + ")");
  return rules.filter(function (rule) {
    return document.querySelector(rule.selector);
  });
}

window.scrapeAnything = { collectImages, runRules };
