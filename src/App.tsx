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
      <div key={node.technique_id || node.technique} className="flex items-center">
        <div className="flex flex-col items-center">
          <div className="flex items-center gap-4">
            {/* Tactic Node */}
            <div className="flex flex-col items-center gap-2">
              <div className="w-16 h-16 bg-[#1A2B44] rounded-xl flex items-center justify-center border border-white/10 shadow-lg group hover:scale-110 transition-transform">
                <UserSearch className="w-8 h-8 text-blue-400" />
              </div>
              <div className="text-center">
                <p className="text-[11px] font-bold uppercase tracking-tight text-[#141414]">{node.tactic}</p>
                <p className="text-[9px] opacity-50 font-mono">(Tactic)</p>
              </div>
            </div>

            <div className="w-12 h-[2px] bg-gradient-to-r from-blue-400 to-blue-600 relative">
              <ArrowRight className="absolute -right-2 -top-[7px] w-4 h-4 text-blue-600" />
            </div>

            {/* Technique Node */}
            <div className="flex flex-col items-center gap-2">
              <div className="w-16 h-16 bg-[#1A2B44] rounded-xl flex items-center justify-center border border-white/10 shadow-lg group hover:scale-110 transition-transform">
                <Activity className="w-8 h-8 text-blue-400" />
              </div>
              <div className="text-center">
                <p className="text-[11px] font-bold uppercase tracking-tight text-[#141414]">{node.technique}</p>
                <p className="text-[9px] opacity-50 font-mono">(Technique)</p>
              </div>
            </div>

            <div className="w-12 h-[2px] bg-gradient-to-r from-blue-400 to-blue-600 relative">
              <ArrowRight className="absolute -right-2 -top-[7px] w-4 h-4 text-blue-600" />
            </div>

            {/* Procedure Node */}
            <div className="flex flex-col items-center gap-2">
              <div className="w-16 h-16 bg-[#1A2B44] rounded-xl flex items-center justify-center border border-white/10 shadow-lg group hover:scale-110 transition-transform">
                <Terminal className="w-8 h-8 text-blue-400" />
              </div>
              <div className="text-center">
                <p className="text-[11px] font-bold uppercase tracking-tight text-[#141414]">{node.procedure}</p>
                <p className="text-[9px] opacity-50 font-mono">(Procedure)</p>
              </div>
            </div>
          </div>
        </div>
        {node.children && node.children.map((child: any) => (
          <div key={child.technique_id} className="flex items-center">
            <div className="w-12 h-[2px] bg-[#141414]/10 mx-4" />
            {renderAttackTreeNode(child, depth + 1)}
          </div>
        ))}
      </div>
    );
  };

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
              <div className="mb-4 p-3 bg-blue-50 border border-blue-200 rounded flex flex-col gap-2">
                <div className="flex items-center gap-2">
                  <div className="bg-blue-600 text-white text-[8px] font-bold px-1.5 py-0.5 rounded uppercase">POC Prompt</div>
                  <span className="text-[10px] font-mono text-blue-800 opacity-70">Copy & Paste:</span>
                </div>
                <p className="text-[10px] font-mono text-blue-900 italic leading-relaxed select-all cursor-pointer hover:text-blue-600 transition-colors" onClick={() => setPrompt("Hunt for suspicious powershell activity that might lead to credential dumping and data exfiltration.")}>
                  "Hunt for suspicious powershell activity that might lead to credential dumping and data exfiltration."
                </p>
              </div>
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
            <h2 className="font-serif italic text-xs uppercase opacity-50 mb-4 tracking-widest">Test Logs (POC Data)</h2>
            <div className="space-y-2 max-h-[200px] overflow-y-auto pr-2 scrollbar-hide">
              {[
                { time: "08:00", event: "Phishing: Invoice.doc", host: "WKSTN-01" },
                { time: "08:05", event: "PowerShell: Encoded", host: "WKSTN-01" },
                { time: "08:10", event: "Schtasks: SystemUpdate", host: "WKSTN-01" },
                { time: "08:20", event: "Mimikatz: LSASS Dump", host: "WKSTN-01" },
                { time: "08:30", event: "RDP: DC-01 Access", host: "WKSTN-01" },
                { time: "09:00", event: "FTP: Data Exfil", host: "DC-01" },
              ].map((log, i) => (
                <div key={i} className="flex items-center gap-3 p-2 border border-[#141414]/10 text-[9px] font-mono hover:bg-[#F5F5F5] transition-colors">
                  <span className="opacity-40">{log.time}</span>
                  <span className="font-bold text-red-600">{log.event}</span>
                  <span className="ml-auto opacity-40">{log.host}</span>
                </div>
              ))}
            </div>
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
                className="space-y-8"
              >
                {/* Full Attack Scenarios (Attack Trees) */}
                <div className="border border-[#141414] bg-white p-6 shadow-[8px_8px_0px_0px_rgba(20,20,20,1)]">
                  <h3 className="font-serif italic text-xs uppercase opacity-50 mb-6 tracking-widest">Full Attack Scenarios (Attack Trees)</h3>
                  <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
                    <div className="lg:col-span-4 space-y-3">
                      {vaultData?.attack_trees?.map((tree: any, idx: number) => (
                        <div 
                          key={idx}
                          onClick={() => setSelectedTreeIdx(idx)}
                          className={cn(
                            "p-4 border border-[#141414] cursor-pointer transition-all",
                            selectedTreeIdx === idx ? "bg-[#141414] text-white" : "bg-white hover:bg-[#F5F5F5]"
                          )}
                        >
                          <p className="text-xs font-bold uppercase tracking-tight">{tree.scenario_name}</p>
                          <p className="text-[10px] opacity-60 mt-1 leading-relaxed">{tree.description}</p>
                        </div>
                      ))}
                    </div>
                    <div className="lg:col-span-8 bg-[#F5F5F5] p-6 border border-[#141414] overflow-x-auto">
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
                  <div className="lg:col-span-5 border border-[#141414] bg-white p-6 shadow-[4px_4px_0px_0px_rgba(20,20,20,1)]">
                    <h3 className="font-serif italic text-xs uppercase opacity-50 mb-6 tracking-widest">Technique Intelligence</h3>
                    <div className="space-y-4 max-h-[500px] overflow-y-auto pr-2 scrollbar-hide">
                      {vaultData?.techniques && Object.entries(vaultData.techniques).map(([id, s]: [string, any]) => (
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
                    {selectedVaultId && vaultData?.techniques?.[selectedVaultId] && (
                      <div className="border border-[#141414] bg-white p-6 shadow-[4px_4px_0px_0px_rgba(20,20,20,1)]">
                        <div className="flex items-center justify-between mb-6">
                          <div>
                            <span className="text-[8px] font-mono uppercase opacity-50 block mb-1">{vaultData.techniques[selectedVaultId].tactic}</span>
                            <h4 className="text-lg font-bold uppercase tracking-tighter">{vaultData.techniques[selectedVaultId].name}</h4>
                          </div>
                          <span className="text-xs font-mono bg-[#141414] text-white px-2 py-1">{selectedVaultId}</span>
                        </div>
                        
                        <div className="space-y-6">
                          <div>
                            <h5 className="font-serif italic text-[10px] uppercase opacity-50 mb-2 tracking-widest">Objective & Execution</h5>
                            <p className="text-sm leading-relaxed opacity-80">{vaultData.techniques[selectedVaultId].description}</p>
                          </div>

                          <div>
                            <h5 className="font-serif italic text-[10px] uppercase opacity-50 mb-2 tracking-widest">Typical Procedure</h5>
                            <p className="text-xs font-mono p-3 bg-[#F5F5F5] border border-[#141414]/10 leading-relaxed">
                              {vaultData.techniques[selectedVaultId].procedure}
                            </p>
                          </div>

                          <div>
                            <h5 className="font-serif italic text-[10px] uppercase opacity-50 mb-2 tracking-widest">Data Sources for Detection</h5>
                            <div className="flex flex-wrap gap-2">
                              {vaultData.techniques[selectedVaultId].data_sources?.map((source: string, idx: number) => (
                                <span key={idx} className="text-[10px] font-mono border border-[#141414] px-2 py-1 bg-[#F5F5F5]">
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
