import { defineConfig } from "vite";

export default defineConfig({
  root: "public",
  envDir: "..",
  publicDir: "../static",
  build: {
    outDir: "../dist",
    emptyOutDir: true,
  },
});
