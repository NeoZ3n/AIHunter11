import express from "express";
import { createServer as createViteServer } from "vite";
import path from "path";
import cors from "cors";
import fs from "fs";
import { getSiemConnector } from "./siem-connectors.js";
import dotenv from "dotenv";

dotenv.config();

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(cors());
  app.use(express.json());

  // SIEM Connector
  const siem = getSiemConnector();
  console.log(`[*] Initialized SIEM Connector: ${siem.name}`);

  // Scenario Vault
  const scenarios = JSON.parse(fs.readFileSync("./scenarios.json", "utf-8"));

  // API: Get Scenario Vault
  app.get("/api/vault", (req, res) => {
    res.json(scenarios);
  });

  /**
   * API: Recursive Hunt
   * This endpoint receives a MITRE ID and performs a multi-stage pivot.
   * It looks up the "next_stages" for the technique in scenarios.json
   * and queries the configured SIEM for each stage.
   */
  app.post("/api/hunt", async (req, res) => {
    const { mitre_id, initial_hits } = req.body;
    const context = { initial_event: initial_hits, follow_ups: [] as any[] };

    if (scenarios[mitre_id]) {
      for (const stage of scenarios[mitre_id].next_stages) {
        console.log(`[*] Pivoting to: ${stage.stage}`);
        try {
          const hits = await siem.search(stage.query);
          if (hits.length > 0) {
            context.follow_ups.push({ stage: stage.stage, technique: stage.technique, hits });
          }
        } catch (error) {
          console.error(`[!] Error searching for stage ${stage.stage}:`, error);
        }
      }
    }
    res.json(context);
  });

  // Vite middleware for development
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

startServer();
