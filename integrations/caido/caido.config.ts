import { defineConfig } from "@caido-community/dev";

export default defineConfig({
  id: "jxscout-rs",
  name: "jxscout-rs",
  description:
    "Forwards in-scope HTML and JavaScript responses to a local jxscout-rs ingest endpoint",
  version: "0.1.0",
  author: {
    name: "jxscout-rs contributors",
    url: "https://github.com/hacker1db/jxscout-rs",
  },
  plugins: [
    {
      kind: "backend",
      id: "jxscout-rs-backend",
      root: "packages/backend",
    },
  ],
});
