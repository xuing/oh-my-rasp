import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// The console is served same-origin with the control-plane API. During local
// development we proxy /api and the health/version endpoints to the Go server
// (defaults to :18090, override with VITE_API_TARGET).
const apiTarget = process.env.VITE_API_TARGET ?? "http://localhost:18090";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    host: true, // bind 0.0.0.0 for remote access
    port: 5273,
    strictPort: true,
    allowedHosts: true, // accept any Host header (remote IP / hostname)
    proxy: {
      "/api": { target: apiTarget, changeOrigin: true },
      "/healthz": { target: apiTarget, changeOrigin: true },
      "/readyz": { target: apiTarget, changeOrigin: true },
      "/v1/version": { target: apiTarget, changeOrigin: true },
      "/metrics": { target: apiTarget, changeOrigin: true }
    }
  },
  build: {
    target: "es2022"
  }
});
