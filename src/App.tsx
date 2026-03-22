import React, { useState, useEffect, useRef } from "react";
import { 
  Search, 
  Shield, 
  Activity, 
  FileText, 
  Terminal, 
  Database, 
  ChevronRight, 
  AlertTriangle, 
  CheckCircle2, 
  Loader2,
  Cpu,
  Zap,
  History
} from "lucide-react";
import { motion, AnimatePresence } from "motion/react";
import { cn } from "./lib/utils";
import { GoogleGenAI, Type } from "@google/genai";

interface Log {
  "@timestamp": string;
  host: { name: string };
  user: { name: string };
  process: { name: string; command_line: string };
  event: { category: string; action: string };
}

interface HuntStage {
  stage: string;
  technique: string;
  hits: Log[];
}

interface HuntContext {
  initial_event: Log[];
  follow_ups: HuntStage[];
}

export default function App() {
  const [prompt, setPrompt] = useState("");
  const [isHunting, setIsHunting] = useState(false);
  const [status, setStatus] = useState<string>("");
  const [huntResult, setHuntResult] = useState<HuntContext | null>(null);
  const [report, setReport] = useState<string | null>(null);
  const [mitreId, setMitreId] = useState<string | null>(null);
  const [kqlQuery, setKqlQuery] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<"dashboard" | "vault" | "report">("dashboard");
  const [vaultData, setVaultData] = useState<any>(null);
  const [selectedVaultId, setSelectedVaultId] = useState<string | null>(null);

  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    fetch("/api/vault")
      .then(res => res.json())
      .then(data => {
        setVaultData(data);
        if (Object.keys(data).length > 0) {
          setSelectedVaultId(Object.keys(data)[0]);
        }
      });
  }, []);

  const handleHunt = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!prompt.trim()) return;

    setIsHunting(true);
    setHuntResult(null);
    setReport(null);
    setMitreId(null);
    setKqlQuery(null);
    setStatus("Translating NL to KQL...");

    try {
      const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY || "" });

      // 1. Translate
      const translateResponse = await ai.models.generateContent({
        model: "gemini-3-flash-preview",
        contents: `Translate this threat hunting request into a valid Elasticsearch KQL query and identify the most relevant MITRE ATT&CK Technique ID.
        Request: "${prompt}"
        Return ONLY a JSON object with keys 'mitre_id' and 'query'.`,
        config: {
          responseMimeType: "application/json",
          responseSchema: {
            type: Type.OBJECT,
            properties: {
              mitre_id: { type: Type.STRING },
              query: { type: Type.STRING }
            },
            required: ["mitre_id", "query"]
          }
        }
      });

      const { mitre_id, query } = JSON.parse(translateResponse.text || "{}");
      setMitreId(mitre_id);
      setKqlQuery(query);

      // 2. Recursive Hunt (Backend still handles mock SIEM search)
      setStatus(`Pivoting based on MITRE ${mitre_id}...`);
      const huntResp = await fetch("/api/hunt", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ mitre_id, initial_hits: [] }),
      });
      const context = await huntResp.json();
      setHuntResult(context);

      // 3. Generate Report
      if (context.follow_ups.length > 0) {
        setStatus("Synthesizing Forensic Report...");
        const reportResponse = await ai.models.generateContent({
          model: "gemini-3-flash-preview",
          contents: `Analyze these threat logs and write a professional forensic report.
          Follow this format:
          # Forensic Report: Aegis Hunter
          ## Summary
          ## Timeline
          ## MITRE ATT&CK Mapping
          ## Remediation Recommendations

          Logs: ${JSON.stringify(context)}`,
        });
        setReport(reportResponse.text || "Report generation failed.");
      }

      setStatus("Hunt Complete.");
    } catch (error) {
      console.error(error);
      setStatus("Error during hunt execution.");
    } finally {
      setIsHunting(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#E4E3E0] text-[#141414] font-sans selection:bg-[#141414] selection:text-[#E4E3E0]">
      {/* Header */}
      <header className="border-b border-[#141414] p-4 flex justify-between items-center bg-[#E4E3E0] sticky top-0 z-50">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 bg-[#141414] flex items-center justify-center rounded-sm">
            <Shield className="text-[#E4E3E0] w-6 h-6" />
          </div>
          <div>
            <h1 className="text-xl font-bold tracking-tighter uppercase">Aegis Hunter</h1>
            <p className="text-[10px] font-mono opacity-60 uppercase tracking-widest">Recursive AI Threat Hunting Engine v1.0</p>
          </div>
        </div>
        <nav className="flex gap-8">
          {[
            { id: "dashboard", label: "Dashboard", icon: Activity },
            { id: "vault", label: "Scenario Vault", icon: Database },
            { id: "report", label: "Forensic Report", icon: FileText },
          ].map((item) => (
            <button
              key={item.id}
              onClick={() => setActiveTab(item.id as any)}
              className={cn(
                "flex items-center gap-2 text-xs font-medium uppercase tracking-wider transition-all hover:opacity-100",
                activeTab === item.id ? "opacity-100 border-b border-[#141414]" : "opacity-40"
              )}
            >
              <item.icon className="w-4 h-4" />
              {item.label}
            </button>
          ))}
        </nav>
      </header>

      <main className="p-6 max-w-7xl mx-auto grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Search & Status */}
        <div className="lg:col-span-4 space-y-6">
          <section className="border border-[#141414] p-6 bg-white shadow-[4px_4px_0px_0px_rgba(20,20,20,1)]">
            <h2 className="font-serif italic text-xs uppercase opacity-50 mb-4 tracking-widest">Initiate Hunt</h2>
            <form onSubmit={handleHunt} className="space-y-4">
              <div className="relative">
                <textarea
                  value={prompt}
                  onChange={(e) => setPrompt(e.target.value)}
                  placeholder="e.g., Find suspicious encoded powershell execution on WKSTN-01"
                  className="w-full bg-[#F5F5F5] border border-[#141414] p-4 text-sm font-mono focus:outline-none focus:ring-1 focus:ring-[#141414] min-h-[120px] resize-none"
                />
                <Search className="absolute bottom-4 right-4 w-5 h-5 opacity-20" />
              </div>
              <button
                disabled={isHunting}
                className="w-full bg-[#141414] text-[#E4E3E0] py-3 text-xs font-bold uppercase tracking-widest flex items-center justify-center gap-2 hover:bg-[#333] transition-colors disabled:opacity-50"
              >
                {isHunting ? <Loader2 className="w-4 h-4 animate-spin" /> : <Zap className="w-4 h-4" />}
                {isHunting ? "Hunting..." : "Execute Recursive Hunt"}
              </button>
            </form>
          </section>

          <section className="border border-[#141414] p-6 bg-white shadow-[4px_4px_0px_0px_rgba(20,20,20,1)]">
            <h2 className="font-serif italic text-xs uppercase opacity-50 mb-4 tracking-widest">Engine Status</h2>
            <div className="space-y-3">
              <div className="flex items-center justify-between text-[10px] font-mono uppercase opacity-60">
                <span>Orchestrator</span>
                <span className="text-green-600">Active</span>
              </div>
              <div className="flex items-center justify-between text-[10px] font-mono uppercase opacity-60">
                <span>SIEM Connector</span>
                <span className="text-green-600">Connected</span>
              </div>
              <div className="flex items-center justify-between text-[10px] font-mono uppercase opacity-60">
                <span>Intelligence Layer</span>
                <span className="text-green-600">Gemini-3-Flash</span>
              </div>
              <div className="mt-4 p-3 bg-[#141414] text-[#E4E3E0] font-mono text-[10px] leading-relaxed">
                <div className="flex items-center gap-2 mb-1">
                  <Terminal className="w-3 h-3" />
                  <span className="opacity-50">LOG_STREAM:</span>
                </div>
                <div className="h-24 overflow-y-auto scrollbar-hide" ref={scrollRef}>
                  <p className="opacity-80">{status || "Waiting for input..."}</p>
                  {isHunting && (
                    <motion.div
                      animate={{ opacity: [0.4, 1, 0.4] }}
                      transition={{ repeat: Infinity, duration: 1.5 }}
                      className="w-1 h-3 bg-white inline-block ml-1"
                    />
                  )}
                </div>
              </div>
            </div>
          </section>
        </div>

        {/* Right Column: Results */}
        <div className="lg:col-span-8">
          <AnimatePresence mode="wait">
            {activeTab === "dashboard" && (
              <motion.div
                key="dashboard"
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -10 }}
                className="space-y-6"
              >
                {/* Hunt Metadata */}
                <div className="grid grid-cols-2 gap-4">
                  <div className="border border-[#141414] p-4 bg-white">
                    <h3 className="font-serif italic text-[10px] uppercase opacity-50 mb-1">Detected Technique</h3>
                    <p className="font-mono text-sm font-bold">{mitreId || "N/A"}</p>
                  </div>
                  <div className="border border-[#141414] p-4 bg-white">
                    <h3 className="font-serif italic text-[10px] uppercase opacity-50 mb-1">Generated KQL</h3>
                    <p className="font-mono text-[10px] truncate opacity-80">{kqlQuery || "N/A"}</p>
                  </div>
                </div>

                {/* Hunt Results Table */}
                <div className="border border-[#141414] bg-white overflow-hidden shadow-[4px_4px_0px_0px_rgba(20,20,20,1)]">
                  <div className="bg-[#141414] text-[#E4E3E0] p-3 flex justify-between items-center">
                    <h3 className="text-[10px] font-bold uppercase tracking-widest flex items-center gap-2">
                      <Activity className="w-3 h-3" />
                      Live Hunt Timeline
                    </h3>
                    <span className="text-[10px] font-mono opacity-50">HITS: {huntResult?.follow_ups.reduce((acc, f) => acc + f.hits.length, 0) || 0}</span>
                  </div>
                  
                  <div className="divide-y divide-[#141414]">
                    {!huntResult && !isHunting && (
                      <div className="p-12 text-center opacity-30">
                        <History className="w-12 h-12 mx-auto mb-4" />
                        <p className="text-xs uppercase font-bold tracking-widest">No active hunt data</p>
                      </div>
                    )}

                    {isHunting && (
                      <div className="p-12 text-center">
                        <Loader2 className="w-8 h-8 mx-auto mb-4 animate-spin opacity-50" />
                        <p className="text-[10px] font-mono uppercase tracking-widest animate-pulse">Scanning SIEM Logs...</p>
                      </div>
                    )}

                    {huntResult?.follow_ups.map((stage, sIdx) => (
                      <div key={sIdx} className="p-4 bg-[#F9F9F9]">
                        <div className="flex items-center gap-2 mb-3">
                          <CheckCircle2 className="w-4 h-4 text-green-600" />
                          <span className="text-[10px] font-bold uppercase tracking-widest">{stage.stage}</span>
                          <span className="text-[10px] font-mono opacity-50 ml-auto">{stage.technique}</span>
                        </div>
                        <div className="space-y-2">
                          {stage.hits.map((log, lIdx) => (
                            <div key={lIdx} className="group border border-[#141414]/10 p-3 hover:bg-[#141414] hover:text-[#E4E3E0] transition-all cursor-crosshair">
                              <div className="flex justify-between text-[10px] font-mono mb-2 opacity-60 group-hover:opacity-100">
                                <span>{log["@timestamp"]}</span>
                                <span>{log.host.name} | {log.user.name}</span>
                              </div>
                              <p className="font-mono text-[11px] break-all leading-relaxed">
                                <span className="text-blue-600 group-hover:text-blue-400 font-bold">{log.process.name}</span>: {log.process.command_line}
                              </p>
                            </div>
                          ))}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </motion.div>
            )}

            {activeTab === "report" && (
              <motion.div
                key="report"
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -10 }}
                className="border border-[#141414] bg-white p-8 shadow-[8px_8px_0px_0px_rgba(20,20,20,1)] min-h-[600px]"
              >
                {!report ? (
                  <div className="h-full flex flex-col items-center justify-center opacity-30">
                    <FileText className="w-16 h-16 mb-4" />
                    <p className="text-xs uppercase font-bold tracking-widest">Execute a hunt to generate report</p>
                  </div>
                ) : (
                  <div className="prose prose-sm max-w-none font-mono text-[#141414]">
                    <div className="whitespace-pre-wrap leading-relaxed">
                      {report}
                    </div>
                  </div>
                )}
              </motion.div>
            )}

            {activeTab === "vault" && (
              <motion.div
                key="vault"
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -10 }}
                className="grid grid-cols-1 lg:grid-cols-12 gap-6"
              >
                <div className="lg:col-span-5 border border-[#141414] bg-white p-6 shadow-[4px_4px_0px_0px_rgba(20,20,20,1)]">
                  <h3 className="font-serif italic text-xs uppercase opacity-50 mb-6 tracking-widest">Scenario Vault</h3>
                  <div className="space-y-4">
                    {vaultData && Object.entries(vaultData).map(([id, s]: [string, any]) => (
                      <div 
                        key={id} 
                        onClick={() => setSelectedVaultId(id)}
                        className={cn(
                          "p-4 border flex items-center justify-between group cursor-pointer transition-all",
                          selectedVaultId === id 
                            ? "bg-[#141414] text-white border-[#141414]" 
                            : "bg-white border-[#141414]/10 hover:border-[#141414]"
                        )}
                      >
                        <div>
                          <p className="text-[10px] font-mono opacity-60 group-hover:opacity-100">{id}</p>
                          <p className="text-xs font-bold uppercase tracking-tight">{s.name}</p>
                        </div>
                        <ChevronRight className={cn("w-4 h-4 opacity-30 group-hover:opacity-100", selectedVaultId === id && "opacity-100")} />
                      </div>
                    ))}
                  </div>
                </div>

                <div className="lg:col-span-7 space-y-6">
                  {selectedVaultId && vaultData?.[selectedVaultId] && (
                    <div className="border border-[#141414] bg-white p-6 shadow-[4px_4px_0px_0px_rgba(20,20,20,1)]">
                      <div className="flex items-center justify-between mb-6">
                        <h4 className="text-lg font-bold uppercase tracking-tighter">{vaultData[selectedVaultId].name}</h4>
                        <span className="text-xs font-mono bg-[#141414] text-white px-2 py-1">{selectedVaultId}</span>
                      </div>
                      
                      <div className="space-y-6">
                        <div>
                          <h5 className="font-serif italic text-[10px] uppercase opacity-50 mb-2 tracking-widest">Objective & Execution</h5>
                          <p className="text-sm leading-relaxed opacity-80">{vaultData[selectedVaultId].description}</p>
                        </div>

                        <div>
                          <h5 className="font-serif italic text-[10px] uppercase opacity-50 mb-2 tracking-widest">Data Sources for Detection</h5>
                          <div className="flex flex-wrap gap-2">
                            {vaultData[selectedVaultId].data_sources?.map((source: string, idx: number) => (
                              <span key={idx} className="text-[10px] font-mono border border-[#141414] px-2 py-1 bg-[#F5F5F5]">
                                {source}
                              </span>
                            ))}
                          </div>
                        </div>

                        <div>
                          <h5 className="font-serif italic text-[10px] uppercase opacity-50 mb-2 tracking-widest">Automated Pivot Stages</h5>
                          <div className="space-y-2">
                            {vaultData[selectedVaultId].next_stages.map((stage: any, idx: number) => (
                              <div key={idx} className="flex items-center gap-3 text-[10px] font-mono p-2 border border-dashed border-[#141414]/30">
                                <span className="bg-[#141414] text-white w-4 h-4 flex items-center justify-center rounded-full text-[8px]">{idx + 1}</span>
                                <span className="font-bold">{stage.stage}</span>
                                <span className="opacity-50 ml-auto">{stage.technique}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      </div>
                    </div>
                  )}

                  <div className="border border-[#141414] bg-[#141414] text-[#E4E3E0] p-6 shadow-[4px_4px_0px_0px_rgba(20,20,20,1)]">
                    <h3 className="font-serif italic text-xs uppercase opacity-50 mb-6 tracking-widest text-white/50">System Architecture</h3>
                    <div className="grid grid-cols-2 gap-6">
                      <div className="flex gap-4">
                        <Cpu className="w-8 h-8 opacity-50 shrink-0" />
                        <div>
                          <p className="text-[10px] font-mono uppercase text-white/40">Orchestrator</p>
                          <p className="text-[10px] leading-relaxed">State machine managing the search-detect-pivot loop. Localized to host.name and time windows.</p>
                        </div>
                      </div>
                      <div className="flex gap-4">
                        <Terminal className="w-8 h-8 opacity-50 shrink-0" />
                        <div>
                          <p className="text-[10px] font-mono uppercase text-white/40">Intelligence Layer</p>
                          <p className="text-[10px] leading-relaxed">Gemini-3-Flash handles NL2KQL translation and forensic synthesis of raw JSON hits.</p>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </main>

      {/* Footer */}
      <footer className="mt-12 border-t border-[#141414] p-4 text-center">
        <p className="text-[10px] font-mono opacity-40 uppercase tracking-[0.2em]">
          Aegis Hunter // Secure Recursive Hunting // 2026
        </p>
      </footer>
    </div>
  );
}
