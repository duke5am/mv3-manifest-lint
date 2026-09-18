// Packaged helper: this one is present on disk, so it produces no finding.
// It is listed in web_accessible_resources (MV2-style) in the manifest.

function debounce(fn, waitMs) {
  let timer = null;
  return function debounced(...args) {
    if (timer) {
      clearTimeout(timer);
    }
    timer = setTimeout(() => fn.apply(this, args), waitMs);
  };
}
