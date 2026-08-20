import { api, setAccessToken } from "./client";

export async function login(email, password) {
  const res = await api.post("/api/auth/login", { email, password });
  setAccessToken(res.data.access_token);
  return res.data;
}

export async function logout() {
  try {
    await api.post("/api/auth/logout");
  } finally {
    setAccessToken(null);
  }
}

export async function fetchMe() {
  const res = await api.get("/api/auth/me");
  return res.data;
}

export async function register(email, password, fullName) {
  const res = await api.post("/api/auth/register", { email, password, full_name: fullName });
  return res.data;
}
