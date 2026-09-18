import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "path";

// The browser only ever talks to the frontend's own origin; /api is forwarded
// to the backend. This mirrors production, where frontend/vercel.json rewrites
// /api to Render, so development and `vite preview` of the built bundle
// exercise the same same-origin cookie and request behaviour as the live site.
const API_TARGET = process.env.VITE_DEV_API_TARGET ?? "http://localhost:8000";

const apiProxy = {
  "/api": {
    target: API_TARGET,
    changeOrigin: false,
    // Hand the backend the browser's address the way Vercel does, so the
    // per-client rate limits and audit log IPs can be checked locally.
    xfwd: true,
  },
};

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  server: {
    port: 5173,
    proxy: apiProxy,
  },
  preview: {
    port: 4173,
    proxy: apiProxy,
  },
});
