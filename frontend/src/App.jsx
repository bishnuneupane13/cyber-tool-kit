import React, { useState, useRef, useEffect } from "react";
import axios from "axios";

const API_BASE = "/api"; // Using relative path since frontend and backend are on same domain

// Tool-specific option definitions
const TOOL_OPTIONS = {
  nmap: {
    name: "Nmap",
    description: "Network mapper - scan ports and services",
    options: [
      { flag: "-sV", label: "Service Version Detection", checked: true },
      { flag: "-sC", label: "Script Scanning", checked: false },
      { flag: "-O", label: "OS Detection", checked: false },
      { flag: "-A", label: "Aggressive Scan", checked: false },
      { flag: "-T4", label: "Timing (T4 - Aggressive)", checked: true },
      { flag: "-p-", label: "All Ports (1-65535)", checked: false },
      { flag: "-p 1-1000", label: "Ports 1-1000", checked: true },
      { flag: "-Pn", label: "Skip Ping", checked: false },
      { flag: "--script vuln", label: "Vulnerability Scripts", checked: false },
    ],
    targetPlaceholder: "example.com or 192.168.1.0/24"
  },
  masscan: {
    name: "Masscan",
    description: "Fast network scanner",
    options: [
      { flag: "-p 1-1000", label: "Ports 1-1000", checked: true },
      { flag: "-p-", label: "All Ports", checked: false },
      { flag: "--rate 1000", label: "Rate: 1000 pps", checked: true },
      { flag: "--rate 10000", label: "Rate: 10000 pps", checked: false },
      { flag: "-e eth0", label: "Interface eth0", checked: false },
    ],
    targetPlaceholder: "192.168.1.0/24 or example.com"
  },
  whois: {
    name: "Whois",
    description: "Domain/IP registrant information",
    options: [
      { flag: "", label: "Standard Lookup", checked: true },
    ],
    targetPlaceholder: "example.com or 1.1.1.1"
  },
  dig: {
    name: "Dig",
    description: "DNS lookup tool",
    options: [
      { flag: "", label: "A Record", checked: true },
      { flag: "+short", label: "Short Output", checked: true },
      { flag: "+trace", label: "Trace Path", checked: false },
      { flag: "@8.8.8.8", label: "Query 8.8.8.8", checked: false },
      { flag: "ANY", label: "All Records", checked: false },
    ],
    targetPlaceholder: "example.com"
  },
  curl: {
    name: "Curl",
    description: "HTTP request tool",
    options: [
      { flag: "-I", label: "Headers Only (-I)", checked: false },
      { flag: "-L", label: "Follow Redirects (-L)", checked: true },
      { flag: "-v", label: "Verbose (-v)", checked: false },
      { flag: "-X POST", label: "POST Request (-X POST)", checked: false },
      { flag: "-H \"User-Agent: Mozilla/5.0\"", label: "Custom User-Agent", checked: true },
      { flag: "-k", label: "Ignore SSL (-k)", checked: false },
    ],
    targetPlaceholder: "http://example.com"
  },
  traceroute: {
    name: "Traceroute",
    description: "Trace route to host",
    options: [
      { flag: "", label: "Standard Traceroute", checked: true },
      { flag: "-m 30", label: "Max Hops: 30", checked: true },
    ],
    targetPlaceholder: "example.com or 1.1.1.1"
  },
  host: {
    name: "Host",
    description: "DNS lookup utility",
    options: [
      { flag: "", label: "Standard Lookup", checked: true },
      { flag: "-v", label: "Verbose", checked: false },
    ],
    targetPlaceholder: "example.com"
  },
  ping: {
    name: "Ping",
    description: "Test host reachability",
    options: [
      { flag: "-c 4", label: "Count: 4 packets", checked: true },
      { flag: "-i 0.2", label: "Interval: 0.2s", checked: false },
    ],
    targetPlaceholder: "example.com or 1.1.1.1"
  },
};

// Legacy presets for quick launch
const PRESETS = {
  nmap: { label: "Nmap quick (-sV 1-1000)", args: ["-sV","-p","1-1000","TARGET"] },
  masscan: { label: "Masscan 1-1000", args: ["-p","1-1000","--rate","1000","TARGET"] },
  whois: { label: "whois lookup", args: ["TARGET"] },
  dig: { label: "dig DNS", args: ["+short","TARGET"] },
};

function splitArgs(raw) {
  if (!raw) return [];
  return raw.match(/(?:[^\s"]+|"[^"]*")+/g).map(s => s.replace(/^"|"$/g, ""));
}

function buildArgsFromOptions(toolName, selectedOptions) {
  // Build args array from selected checkboxes
  const args = [];
  if (TOOL_OPTIONS[toolName]) {
    TOOL_OPTIONS[toolName].options.forEach((opt, idx) => {
      if (selectedOptions[idx]) {
        if (opt.flag) {
          const parts = opt.flag.split(/\s+/).filter(Boolean);
          args.push(...parts);
        }
      }
    });
  }
  return args;
}

function ToolOptionsBuilder({ tool, onArgsChange }) {
  const toolDef = TOOL_OPTIONS[tool];
  if (!toolDef) return null;

  const [selected, setSelected] = useState(toolDef.options.map(o => o.checked));

  useEffect(() => {
    const args = buildArgsFromOptions(tool, selected);
    onArgsChange(args.join(" "));
  }, [selected, tool, onArgsChange]);

  return (
    <div className="card" style={{marginBottom: 12, padding: "8px 12px", backgroundColor: "#0f1419"}}>
      <h4 style={{marginTop: 0, marginBottom: 8, fontSize: "14px"}}>{toolDef.name}</h4>
      <p style={{marginTop: 0, marginBottom: 8, fontSize: "12px", color: "#8b949e"}}>{toolDef.description}</p>
      <div style={{display: "grid", gridTemplateColumns: "1fr 1fr", gap: "6px"}}>
        {toolDef.options.map((opt, idx) => (
          <label key={idx} style={{display: "flex", alignItems: "center", fontSize: "12px", cursor: "pointer"}}>
            <input
              type="checkbox"
              checked={selected[idx]}
              onChange={e => {
                const newSel = [...selected];
                newSel[idx] = e.target.checked;
                setSelected(newSel);
              }}
              style={{marginRight: 6}}
            />
            <span>{opt.label}</span>
          </label>
        ))}
      </div>
    </div>
  );
}


export default function App() {
  const [tool, setTool] = useState("nmap");
  const [target, setTarget] = useState("example.com");
  const [argsText, setArgsText] = useState("");
  const [logs, setLogs] = useState([]);
  const [running, setRunning] = useState(false);
  const [jobs, setJobs] = useState([]);
  const [showOptions, setShowOptions] = useState(true);
  const terminalRef = useRef(null);

  useEffect(()=>{ refreshJobs(); }, []);

  function applyPreset(t) {
    const p = PRESETS[t];
    if (!p) return;
    const arr = p.args.map(a => a.replace(/TARGET/g, target));
    setArgsText(arr.join(" "));
  }

  async function refreshJobs() {
    try {
      const r = await axios.get(`${API_BASE}/jobs`);
      setJobs(Object.keys(r.data).slice(0,30));
    } catch (e) {
      console.error(e);
    }
  }

  async function runTool() {
    setLogs([]);
    setRunning(true);
    const argsArr = splitArgs(argsText).map(a => a.replace(/TARGET/g, target));
    try {
      const resp = await fetch(`${API_BASE}/exec`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ tool, args: argsArr })
      });
      if (!resp.ok) {
        const j = await resp.json().catch(()=>({error:resp.statusText}));
        setLogs(prev => [...prev, "ERROR: " + (j.error || resp.statusText)]);
        setRunning(false);
        return;
      }
      const reader = resp.body.getReader();
      const dec = new TextDecoder();
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        const chunk = dec.decode(value, { stream: true });
        // split lines and remove SSE "data:" prefixes if present
        const parts = chunk.split(/\r?\n/).filter(Boolean);
        parts.forEach(p => {
          const line = p.replace(/^data:\s?/, "");
          setLogs(prev => {
            const next = [...prev, line];
            return next.slice(-2000);
          });
        });
        // auto-scroll
        if (terminalRef.current) terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
      }
      setLogs(prev => [...prev, "=== stream ended ==="]);
    } catch (e) {
      setLogs(prev => [...prev, "ERROR: " + (e.message || e)]);
    } finally {
      setRunning(false);
      refreshJobs();
    }
  }

  function stopRun() {
    // no reliable client kill in this simple setup; implement /api/kill on backend if needed
    setLogs(prev => [...prev, "Stop requested (client). Implement server-side kill to actually stop process."]);
  }

  const toolDef = TOOL_OPTIONS[tool];
  const targetPlaceholder = toolDef ? toolDef.targetPlaceholder : "target";

  return (
    <div className="container">
      <div className="card">
        <h2>🛠️ Cyber Tool Kit — Advanced Options</h2>
        
        <div className="row" style={{marginTop:12}}>
          <div style={{flex: 1}}>
            {/* Tool & Target Selection */}
            <div style={{display:"flex", gap:8, marginBottom: 12}}>
              <select value={tool} onChange={e=>{ setTool(e.target.value); applyPreset(e.target.value); }} className="input" style={{flex: 1}}>
                {Object.keys(TOOL_OPTIONS).map(k => {
                  const def = TOOL_OPTIONS[k];
                  return <option key={k} value={k}>{def.name} — {def.description}</option>;
                })}
              </select>
            </div>

            {/* Target Input */}
            <div style={{marginBottom: 12}}>
              <label className="small">Target</label>
              <input 
                className="input" 
                value={target} 
                onChange={e=>setTarget(e.target.value)} 
                placeholder={targetPlaceholder}
                style={{width: "100%"}}
              />
            </div>

            {/* Tool-Specific Options */}
            {showOptions && (
              <ToolOptionsBuilder tool={tool} onArgsChange={setArgsText} />
            )}

            {/* Custom Args Override */}
            <div style={{marginBottom: 12}}>
              <label className="small">
                Custom Arguments (or edit the auto-generated ones above)
              </label>
              <textarea 
                className="input" 
                value={argsText} 
                onChange={e=>setArgsText(e.target.value)}
                placeholder="-sV -p 1-1000 (space-separated flags)"
                style={{width: "100%", height: "60px", fontFamily: "monospace"}}
              />
            </div>

            {/* Control Buttons */}
            <div style={{marginBottom: 12}}>
              <button className="button btn-primary" onClick={runTool} disabled={running} style={{marginRight:8}}>
                {running ? "⏳ Running..." : "▶️ Run"}
              </button>
              <button className="button btn-ghost" onClick={stopRun} disabled={!running} style={{marginRight: 8}}>Stop</button>
              <button className="button btn-ghost" onClick={()=>setShowOptions(!showOptions)} style={{marginRight: 8}}>
                {showOptions ? "Hide Options" : "Show Options"}
              </button>
              <button className="button btn-ghost" onClick={refreshJobs}>Refresh Jobs</button>
            </div>

            {/* Terminal Output */}
            <div ref={terminalRef} className="terminal" style={{marginTop:12, minHeight: "300px"}}>
              {logs.length===0 ? <div style={{color:"#99a3a4"}}>Terminal output will appear here...</div> : logs.map((l,i)=> <div key={i}>{l}</div>)}
            </div>
          </div>

          {/* Right Sidebar */}
          <div style={{width:320, marginLeft:12}}>
            <div className="card">
              <h4>📋 Recent Jobs</h4>
              <ul className="side-list">
                {jobs.length===0 && <li className="small">no jobs yet</li>}
                {jobs.map(j => (
                  <li key={j}><a className="link" href={`${API_BASE}/result/${j}`} target="_blank" rel="noreferrer">{j.substring(0, 24)}...</a></li>
                ))}
              </ul>
            </div>

            <div className="card" style={{marginTop:12}}>
              <h4>💡 Tips</h4>
              <ul className="side-list" style={{fontSize: "12px"}}>
                <li>Use checkboxes to build custom commands</li>
                <li>Replace "TARGET" in args with your target</li>
                <li>Each flag generates actual CLI args</li>
                <li>All scans run with selected options</li>
              </ul>
            </div>

            <div className="card" style={{marginTop:12}}>
              <h4>🔗 Resources</h4>
              <ul className="side-list">
                <li><a className="link" href="https://nmap.org/book/man.html" target="_blank" rel="noreferrer">Nmap Manual</a></li>
                <li><a className="link" href="https://www.gnu.org/software/wget/manual/" target="_blank" rel="noreferrer">Curl Docs</a></li>
                <li><a className="link" href="https://linux.die.net/man/1/dig" target="_blank" rel="noreferrer">Dig Manual</a></li>
              </ul>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
