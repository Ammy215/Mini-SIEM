// FastAPI sends `detail` as a string for errors the API raises itself, and as
// a list of {loc, msg} objects for request-validation errors.
export function apiErrorMessage(err, fallback) {
  const detail = err?.response?.data?.detail;
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) return detail.map((d) => d.msg).join("; ");
  return fallback;
}
