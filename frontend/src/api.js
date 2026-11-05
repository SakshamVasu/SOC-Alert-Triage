// Thin wrapper around the Flask API. Every call throws an Error carrying the
// backend's {"error": "..."} message so the UI can show it verbatim.

async function request(path, options = {}) {
  const res = await fetch(`/api${path}`, options);
  let body = null;
  try {
    body = await res.json();
  } catch {
    // non-JSON response (e.g. backend not running and the proxy returned HTML)
  }
  if (!res.ok) {
    throw new Error(body?.error || `Request failed (${res.status}). Is the Flask backend running on port 5000?`);
  }
  return body;
}

function query(filters) {
  const params = new URLSearchParams();
  Object.entries(filters).forEach(([key, value]) => {
    if (Array.isArray(value) ? value.length : value) {
      params.set(key, Array.isArray(value) ? value.join(",") : value);
    }
  });
  const qs = params.toString();
  return qs ? `?${qs}` : "";
}

export const api = {
  health: () => request("/health"),
  upload: (file) => {
    const form = new FormData();
    form.append("file", file);
    return request("/upload", { method: "POST", body: form });
  },
  alerts: (filters) => request(`/alerts${query(filters)}`),
  alert: (id) => request(`/alerts/${id}`),
  stats: (filters) => request(`/stats${query(filters)}`),
  clear: () => request("/alerts", { method: "DELETE" }),
  reloadRules: () => request("/rules/reload", { method: "POST" }),
  summarize: (id) => request(`/alerts/${id}/summarize`, { method: "POST" }),
};

export const SEVERITIES = ["critical", "high", "medium", "low", "informational"];
