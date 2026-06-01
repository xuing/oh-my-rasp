import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

const apiProxyTarget = process.env.VITE_API_PROXY_TARGET ?? "http://localhost:8080";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  build: {
    rolldownOptions: {
      output: {
        codeSplitting: {
          groups: [
            {
              name: "react-vendor",
              test: /node_modules[\\/](react|react-dom)[\\/]/,
              priority: 30
            },
            {
              name: "router-query",
              test: /node_modules[\\/]@tanstack[\\/]/,
              priority: 25
            },
            {
              name: "icons",
              test: /node_modules[\\/]lucide-react[\\/]/,
              priority: 20
            },
            {
              name: "i18n",
              test: /node_modules[\\/](i18next|react-i18next)[\\/]/,
              priority: 15
            },
            {
              name: "vendor",
              test: /node_modules[\\/]/,
              priority: 1
            }
          ]
        }
      }
    }
  },
  server: {
    host: "0.0.0.0",
    port: 5173,
    proxy: {
      "/api": apiProxyTarget
    }
  },
  test: {
    environment: "jsdom",
    globals: true,
    include: ["src/**/*.test.ts", "src/**/*.test.tsx"],
    setupFiles: ["./src/test/setup.ts"]
  }
});
