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
  History,
  UserSearch,
  ArrowRight
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
  const [selectedTreeIdx, setSelectedTreeIdx] = useState<number | null>(null);

  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    fetch("/api/vault")
      .then(res => res.json())
      .then(data => {
        setVaultData(data);
        if (data.techniques && Object.keys(data.techniques).length > 0) {
          setSelectedVaultId(Object.keys(data.techniques)[0]);
        }
        if (data.attack_trees && data.attack_trees.length > 0) {
          setSelectedTreeIdx(0);
        }
      });
  }, []);

  const renderAttackTreeNode = (node: any, depth: number = 0) => {
    return (
      <div key={node.technique_id || node.technique} className="flex items-start">
        <div className="flex flex-col items-center">
          {/* Vertical Stack for Tactic -> Technique -> Procedure */}
          <div className="flex flex-col items-center gap-3">
            {/* Tactic Node */}
            <div className="flex flex-col items-center gap-1">
              <div className="w-10 h-10 bg-secops-primary/10 rounded-lg flex items-center justify-center border border-secops-primary/30 shadow-[0_0_10px_rgba(26,115,232,0.1)] group hover:scale-105 transition-all">
                <UserSearch className="w-5 h-5 text-secops-accent" />
              </div>
              <div className="text-center w-24">
                <p className="text-[8px] font-bold uppercase tracking-tight text-secops-text truncate">{node.tactic}</p>
                <p className="text-[6px] text-secops-muted font-mono uppercase">Tactic</p>
              </div>
            </div>

            <div className="h-3 w-[1px] bg-secops-border relative">
              <div className="absolute -bottom-1 -left-[2px] w-1 h-1 border-b border-r border-secops-border rotate-45" />
            </div>

            {/* Technique Node */}
            <div className="flex flex-col items-center gap-1">
              <div className="w-10 h-10 bg-secops-primary/10 rounded-lg flex items-center justify-center border border-secops-primary/30 shadow-[0_0_10px_rgba(26,115,232,0.1)] group hover:scale-105 transition-all">
                <Activity className="w-5 h-5 text-secops-accent" />
              </div>
              <div className="text-center w-24">
                <p className="text-[8px] font-bold uppercase tracking-tight text-secops-text truncate">{node.technique}</p>
                <p className="text-[6px] text-secops-muted font-mono uppercase">Technique</p>
              </div>
            </div>

            <div className="h-3 w-[1px] bg-secops-border relative">
              <div className="absolute -bottom-1 -left-[2px] w-1 h-1 border-b border-r border-secops-border rotate-45" />
            </div>

            {/* Procedure Node */}
            <div className="flex flex-col items-center gap-1">
              <div className="w-10 h-10 bg-secops-primary/10 rounded-lg flex items-center justify-center border border-secops-primary/30 shadow-[0_0_10px_rgba(26,115,232,0.1)] group hover:scale-105 transition-all">
                <Terminal className="w-5 h-5 text-secops-accent" />
              </div>
              <div className="text-center w-24">
                <p className="text-[8px] font-bold uppercase tracking-tight text-secops-text truncate">{node.procedure}</p>
                <p className="text-[6px] text-secops-muted font-mono uppercase">Procedure</p>
              </div>
            </div>
          </div>
        </div>

        {/* Children (Horizontal Chaining) */}
        {node.children && node.children.length > 0 && (
          <div className="flex items-start">
            <div className="w-8 h-[1px] bg-secops-border relative mt-5">
              <ArrowRight className="absolute -right-1 -top-[7px] w-3 h-3 text-secops-muted" />
            </div>
            <div className="flex flex-col gap-12 border-l border-secops-border/30 pl-4 py-2">
              {node.children.map((child: any) => (
                <div key={child.technique_id || child.technique} className="relative">
                  {/* Diagonal-ish connection line for multiple children */}
                  {node.children.length > 1 && (
                    <div className="absolute -left-4 top-5 w-4 h-[1px] bg-secops-border/30" />
                  )}
                  {renderAttackTreeNode(child, depth + 1)}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    );
  };

  /**
   * handleHunt: The core orchestration function for the threat hunt.
   * 1. Translates natural language to MITRE ID and KQL using Gemini AI.
   * 2. Calls the backend /api/hunt for recursive pivoting through attack stages.
   * 3. Synthesizes a final forensic report based on all discovered evidence.
   */
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
    <div className="min-h-screen bg-secops-bg text-secops-text font-sans selection:bg-secops-primary selection:text-white">
      {/* Header */}
      <header className="border-b border-secops-border p-4 flex justify-between items-center bg-secops-surface/80 backdrop-blur-md sticky top-0 z-50">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 bg-secops-primary flex items-center justify-center rounded-lg shadow-[0_0_20px_rgba(26,115,232,0.3)]">
            <Shield className="text-white w-6 h-6" />
          </div>
          <div>
            <h1 className="text-xl font-bold tracking-tighter uppercase text-secops-text">Aegis Hunter</h1>
            <p className="text-[10px] font-mono text-secops-muted uppercase tracking-widest">Recursive AI Threat Hunting Engine v1.0</p>
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
                "flex items-center gap-2 text-xs font-medium uppercase tracking-wider transition-all hover:text-secops-accent",
                activeTab === item.id ? "text-secops-accent border-b-2 border-secops-accent pb-1" : "text-secops-muted"
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
          <section className="glass-panel p-6">
            <h2 className="text-[10px] font-bold uppercase text-secops-muted mb-4 tracking-widest">Initiate Hunt</h2>
            <form onSubmit={handleHunt} className="space-y-4">
              <div className="mb-4 p-3 bg-secops-primary/5 border border-secops-primary/20 rounded-lg flex flex-col gap-2">
                <div className="flex items-center gap-2">
                  <div className="bg-secops-primary text-white text-[8px] font-bold px-1.5 py-0.5 rounded uppercase">POC Prompt</div>
                  <span className="text-[10px] font-mono text-secops-muted opacity-70">Copy & Paste:</span>
                </div>
                <p className="text-[10px] font-mono text-secops-accent italic leading-relaxed select-all cursor-pointer hover:text-white transition-colors" onClick={() => setPrompt("Hunt for suspicious powershell activity that might lead to credential dumping and data exfiltration.")}>
                  "Hunt for suspicious powershell activity that might lead to credential dumping and data exfiltration."
                </p>
              </div>
              <div className="relative">
                <textarea
                  value={prompt}
                  onChange={(e) => setPrompt(e.target.value)}
                  placeholder="e.g., Find suspicious encoded powershell execution on WKSTN-01"
                  className="w-full bg-secops-bg border border-secops-border rounded-lg p-4 text-sm font-mono text-secops-text focus:outline-none focus:border-secops-primary transition-all min-h-[120px] resize-none"
                />
                <Search className="absolute bottom-4 right-4 w-5 h-5 opacity-20" />
              </div>
              <button
                disabled={isHunting}
                className="w-full bg-secops-primary text-white py-3 rounded-lg text-xs font-bold uppercase tracking-widest flex items-center justify-center gap-2 hover:bg-secops-primary/90 transition-all disabled:opacity-50 shadow-lg shadow-secops-primary/20"
              >
                {isHunting ? <Loader2 className="w-4 h-4 animate-spin" /> : <Zap className="w-4 h-4" />}
                {isHunting ? "Hunting..." : "Execute Recursive Hunt"}
              </button>
            </form>
          </section>

          <section className="glass-panel p-6">
            <h2 className="text-[10px] font-bold uppercase text-secops-muted mb-4 tracking-widest">Test Logs (POC Data)</h2>
            <div className="space-y-2 max-h-[200px] overflow-y-auto pr-2 scrollbar-hide">
              {[
                { time: "08:00", event: "Phishing: Invoice.doc", host: "WKSTN-01" },
                { time: "08:05", event: "PowerShell: Encoded", host: "WKSTN-01" },
                { time: "08:10", event: "Schtasks: SystemUpdate", host: "WKSTN-01" },
                { time: "08:20", event: "Mimikatz: LSASS Dump", host: "WKSTN-01" },
                { time: "08:30", event: "RDP: DC-01 Access", host: "WKSTN-01" },
                { time: "09:00", event: "FTP: Data Exfil", host: "DC-01" },
              ].map((log, i) => (
                <div key={i} className="flex items-center gap-3 p-2 border border-secops-border/50 rounded bg-secops-bg/50 text-[9px] font-mono hover:bg-secops-surface transition-colors">
                  <span className="text-secops-muted">{log.time}</span>
                  <span className="font-bold text-red-400">{log.event}</span>
                  <span className="ml-auto text-secops-muted">{log.host}</span>
                </div>
              ))}
            </div>
          </section>

          <section className="glass-panel p-6">
            <h2 className="text-[10px] font-bold uppercase text-secops-muted mb-4 tracking-widest">Engine Status</h2>
            <div className="space-y-3">
              <div className="flex items-center justify-between text-[10px] font-mono uppercase text-secops-muted">
                <span>Orchestrator</span>
                <span className="text-green-400">Active</span>
              </div>
              <div className="flex items-center justify-between text-[10px] font-mono uppercase text-secops-muted">
                <span>SIEM Connector</span>
                <span className="text-green-400">Connected</span>
              </div>
              <div className="flex items-center justify-between text-[10px] font-mono uppercase text-secops-muted">
                <span>Intelligence Layer</span>
                <span className="text-green-400">Gemini-3-Flash</span>
              </div>
              <div className="mt-4 p-3 bg-secops-bg rounded-lg border border-secops-border font-mono text-[10px] leading-relaxed">
                <div className="flex items-center gap-2 mb-1">
                  <Terminal className="w-3 h-3 text-secops-accent" />
                  <span className="text-secops-muted">LOG_STREAM:</span>
                </div>
                <div className="h-24 overflow-y-auto scrollbar-hide" ref={scrollRef}>
                  <p className="text-secops-text">{status || "Waiting for input..."}</p>
                  {isHunting && (
                    <motion.div
                      animate={{ opacity: [0.4, 1, 0.4] }}
                      transition={{ repeat: Infinity, duration: 1.5 }}
                      className="w-1 h-3 bg-secops-accent inline-block ml-1"
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
                  <div className="glass-panel p-4">
                    <h3 className="text-[10px] font-bold uppercase text-secops-muted mb-1 tracking-widest">Detected Technique</h3>
                    <p className="font-mono text-sm font-bold text-secops-accent">{mitreId || "N/A"}</p>
                  </div>
                  <div className="glass-panel p-4">
                    <h3 className="text-[10px] font-bold uppercase text-secops-muted mb-1 tracking-widest">Generated KQL</h3>
                    <p className="font-mono text-[10px] truncate text-secops-text/80">{kqlQuery || "N/A"}</p>
                  </div>
                </div>

                {/* Hunt Results Table */}
                <div className="glass-panel overflow-hidden">
                  <div className="p-4 border-b border-secops-border bg-secops-surface/50 flex items-center justify-between">
                    <h3 className="text-[10px] font-bold uppercase text-secops-muted flex items-center gap-2">
                      <Activity className="w-3 h-3 text-secops-accent" />
                      Live Hunt Timeline
                    </h3>
                    <span className="text-[10px] font-mono text-secops-muted">HITS: {huntResult?.follow_ups.reduce((acc, f) => acc + f.hits.length, 0) || 0}</span>
                  </div>
                  
                  <div className="divide-y divide-secops-border">
                    {!huntResult && !isHunting && (
                      <div className="p-24 text-center opacity-30">
                        <History className="w-12 h-12 mx-auto mb-4" />
                        <p className="text-xs uppercase font-bold tracking-widest">No active hunt data</p>
                      </div>
                    )}

                    {isHunting && (
                      <div className="p-24 text-center">
                        <Loader2 className="w-8 h-8 mx-auto mb-4 animate-spin text-secops-primary" />
                        <p className="text-[10px] font-mono uppercase tracking-widest animate-pulse text-secops-muted">Scanning SIEM Logs...</p>
                      </div>
                    )}

                    {huntResult?.follow_ups.map((stage, sIdx) => (
                      <div key={sIdx} className="p-4 bg-secops-surface/30">
                        <div className="flex items-center gap-2 mb-3">
                          <CheckCircle2 className="w-4 h-4 text-green-400" />
                          <span className="text-[10px] font-bold uppercase tracking-widest text-secops-text">{stage.stage}</span>
                          <span className="text-[10px] font-mono text-secops-muted ml-auto">{stage.technique}</span>
                        </div>
                        <div className="space-y-2">
                          {stage.hits.map((log, lIdx) => (
                            <div key={lIdx} className="group border border-secops-border/50 rounded-lg p-3 bg-secops-bg/50 hover:bg-secops-surface hover:border-secops-primary/50 transition-all cursor-crosshair">
                              <div className="flex justify-between text-[10px] font-mono mb-2 text-secops-muted group-hover:text-secops-text">
                                <span>{log["@timestamp"]}</span>
                                <span>{log.host.name} | {log.user.name}</span>
                              </div>
                              <p className="font-mono text-[11px] break-all leading-relaxed">
                                <span className="text-secops-accent font-bold">{log.process.name}</span>: <span className="text-secops-text/80">{log.process.command_line}</span>
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
                className="glass-panel p-8 min-h-[600px]"
              >
                {!report ? (
                  <div className="h-full flex flex-col items-center justify-center opacity-30">
                    <FileText className="w-16 h-16 mb-4" />
                    <p className="text-xs uppercase font-bold tracking-widest">Execute a hunt to generate report</p>
                  </div>
                ) : (
                  <div className="prose prose-invert prose-sm max-w-none font-mono text-secops-text">
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
                className="space-y-8"
              >
                {/* Full Attack Scenarios (Attack Trees) */}
                <div className="glass-panel p-6">
                  <h3 className="text-[10px] font-bold uppercase text-secops-muted mb-6 tracking-widest">Full Attack Scenarios (Attack Trees)</h3>
                  <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
                    <div className="lg:col-span-4 space-y-3">
                      {vaultData?.attack_trees?.map((tree: any, idx: number) => (
                        <div 
                          key={idx}
                          onClick={() => setSelectedTreeIdx(idx)}
                          className={cn(
                            "p-4 rounded-lg border cursor-pointer transition-all",
                            selectedTreeIdx === idx ? "bg-secops-primary text-white border-secops-primary shadow-lg shadow-secops-primary/20" : "bg-secops-bg border-secops-border hover:border-secops-muted"
                          )}
                        >
                          <p className="text-xs font-bold uppercase tracking-tight">{tree.scenario_name}</p>
                          <p className="text-[10px] opacity-60 mt-1 leading-relaxed">{tree.description}</p>
                        </div>
                      ))}
                    </div>
                    <div className="lg:col-span-8 bg-secops-bg/50 rounded-xl p-6 border border-secops-border overflow-x-auto">
                      <div className="min-w-[400px]">
                        {selectedTreeIdx !== null && vaultData?.attack_trees?.[selectedTreeIdx] && (
                          renderAttackTreeNode(vaultData.attack_trees[selectedTreeIdx].root)
                        )}
                      </div>
                    </div>
                  </div>
                </div>

                {/* Technique Intelligence */}
                <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
                  <div className="lg:col-span-5 glass-panel p-6">
                    <h3 className="text-[10px] font-bold uppercase text-secops-muted mb-6 tracking-widest">Technique Intelligence</h3>
                    <div className="space-y-4 max-h-[500px] overflow-y-auto pr-2 scrollbar-hide">
                      {vaultData?.techniques && Object.entries(vaultData.techniques).map(([id, s]: [string, any]) => (
                        <div 
                          key={id} 
                          onClick={() => setSelectedVaultId(id)}
                          className={cn(
                            "p-4 rounded-lg border flex items-center justify-between group cursor-pointer transition-all",
                            selectedVaultId === id 
                              ? "bg-secops-primary text-white border-secops-primary shadow-lg shadow-secops-primary/20" 
                              : "bg-secops-bg border-secops-border hover:border-secops-muted"
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
                    {selectedVaultId && vaultData?.techniques?.[selectedVaultId] && (
                      <div className="glass-panel p-6">
                        <div className="flex items-center justify-between mb-6">
                          <div>
                            <span className="text-[8px] font-mono uppercase text-secops-muted block mb-1">{vaultData.techniques[selectedVaultId].tactic}</span>
                            <h4 className="text-lg font-bold uppercase tracking-tighter text-secops-text">{vaultData.techniques[selectedVaultId].name}</h4>
                          </div>
                          <span className="text-xs font-mono bg-secops-primary text-white px-2 py-1 rounded">{selectedVaultId}</span>
                        </div>
                        
                        <div className="space-y-6">
                          <div>
                            <h5 className="text-[10px] font-bold uppercase text-secops-muted mb-2 tracking-widest">Objective & Execution</h5>
                            <p className="text-sm leading-relaxed text-secops-text/80">{vaultData.techniques[selectedVaultId].description}</p>
                          </div>

                          <div>
                            <h5 className="text-[10px] font-bold uppercase text-secops-muted mb-2 tracking-widest">Typical Procedure</h5>
                            <p className="text-xs font-mono p-3 bg-secops-bg rounded-lg border border-secops-border leading-relaxed text-secops-accent">
                              {vaultData.techniques[selectedVaultId].procedure}
                            </p>
                          </div>

                          <div>
                            <h5 className="text-[10px] font-bold uppercase text-secops-muted mb-2 tracking-widest">Data Sources for Detection</h5>
                            <div className="flex flex-wrap gap-2">
                              {vaultData.techniques[selectedVaultId].data_sources?.map((source: string, idx: number) => (
                                <span key={idx} className="text-[10px] font-mono border border-secops-border px-2 py-1 bg-secops-bg rounded text-secops-muted">
                                  {source}
                                </span>
                              ))}
                            </div>
                          </div>
                        </div>
                      </div>
                    )}
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
