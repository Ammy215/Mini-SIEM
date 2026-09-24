// FastAPI sends `detail` as a string for errors the API raises itself, and as
// a list of {loc, msg} objects for request-validation errors.

// Render's edge firewall rejects some requests before they reach the app —
// anything carrying text that looks like a web attack, such as `' OR 1=1--`,
// `../../etc/passwd` or `${jndi:…}` (FUTURE_UPGRADES.md 4.18). It answers 403
// with an HTML page. The app's own refusals are always JSON with a `detail`, so
// a 403 that is not JSON can only come from the hosting layer.
export function isEdgeBlock(err) {
  const response = err?.response;
  if (response?.status !== 403) return false;
  if (typeof response.data?.detail === "string" || Array.isArray(response.data?.detail)) return false;
  const contentType = String(response.headers?.["content-type"] ?? "");
  return !contentType.includes("application/json");
}

export const EDGE_BLOCK_MESSAGE =
  "Blocked by the hosting provider's firewall before it reached Mini SIEM: the request contains text " +
  "that looks like a web attack, such as SQL injection, ../../etc/passwd or ${jndi:…}.";

export const EDGE_BLOCK_UPLOAD_MESSAGE =
  "The hosting provider's firewall blocked this upload before it reached Mini SIEM, because the file " +
  "contains text that looks like a web attack — such as SQL injection, ../../etc/passwd or ${jndi:…}. " +
  "Your file isn't broken. Remove or redact those lines to upload the rest.";

export function apiErrorMessage(err, fallback) {
  if (isEdgeBlock(err)) return EDGE_BLOCK_MESSAGE;
  const detail = err?.response?.data?.detail;
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) return detail.map((d) => d.msg).join("; ");
  return fallback;
}
