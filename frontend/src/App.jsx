import React, { useState, useRef, useEffect } from "react";
import axios from "axios";

const API_BASE = "/api"; // Using relative path since frontend and backend are on same domain

// Tool-specific option definitions with detailed help
const TOOL_OPTIONS = {
  nmap: {
    name: "Nmap",
    description: "Network mapper - scan ports and services",
    fullGuide: {
      what: "Nmap is a powerful network scanning tool that discovers hosts, ports, and services on a network.",
      when: "Use for network reconnaissance, port scanning, service enumeration, vulnerability detection.",
      examples: [
        "nmap -sV example.com (detect service versions)",
        "nmap -sC -sV example.com (safe scripts + version detection)",
        "nmap -A example.com (aggressive: OS + service + script scanning)",
        "nmap -p- example.com (scan all 65535 ports)"
      ],
      risks: "⚠️ Aggressive scanning may trigger intrusion detection systems. Always get permission before scanning."
    },
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
    fullGuide: {
      what: "Masscan is an extremely fast port scanner that can scan the entire internet in under 6 minutes.",
      when: "Use for fast, large-scale port scanning with high packet rates.",
      examples: [
        "masscan 192.168.1.0/24 -p 1-1000",
        "masscan example.com -p- --rate 10000",
        "masscan 10.0.0.0/8 -p 80,443 --rate 100000"
      ],
      risks: "⚠️ Very aggressive scanning. Can overwhelm network infrastructure. Requires root/admin."
    },
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
    fullGuide: {
      what: "Whois queries the registrar databases to find domain and IP ownership information.",
      when: "Use for OSINT (Open Source Intelligence) gathering, domain reconnaissance.",
      examples: [
        "whois example.com",
        "whois 1.1.1.1",
        "whois -h whois.arin.net 192.0.2.0"
      ],
      risks: "Safe - Public database queries. No enumeration risk."
    },
    options: [
      { flag: "", label: "Standard Lookup", checked: true },
    ],
    targetPlaceholder: "example.com or 1.1.1.1"
  },
  dig: {
    name: "Dig",
    description: "DNS lookup tool",
    fullGuide: {
      what: "Dig (Domain Information Groper) performs DNS lookups and shows detailed query information.",
      when: "Use for DNS reconnaissance, zone transfer attempts, subdomain enumeration.",
      examples: [
        "dig example.com +short",
        "dig example.com ANY",
        "dig @8.8.8.8 example.com",
        "dig example.com +trace (trace DNS path)"
      ],
      risks: "Relatively safe - DNS queries are usually logged but not blocked."
    },
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
    fullGuide: {
      what: "Curl is a command-line HTTP client for making web requests, testing APIs, and website crawling.",
      when: "Use for HTTP testing, API calls, web server enumeration, SSL/TLS testing.",
      examples: [
        "curl -I http://example.com (headers only)",
        "curl -v http://example.com (verbose)",
        "curl -X POST -d 'data' http://example.com",
        "curl -k https://example.com (ignore SSL)"
      ],
      risks: "Depends on target - GET requests are generally safe, but POST/PUT can cause state changes."
    },
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
    fullGuide: {
      what: "Traceroute maps the network path taken by packets to reach a destination host.",
      when: "Use for network path analysis, identifying latency issues, finding intermediate routers.",
      examples: [
        "traceroute example.com",
        "traceroute -m 30 example.com",
        "traceroute -I example.com (ICMP mode)"
      ],
      risks: "Safe - Network diagnostic tool. May be rate-limited or blocked by firewalls."
    },
    options: [
      { flag: "", label: "Standard Traceroute", checked: true },
      { flag: "-m 30", label: "Max Hops: 30", checked: true },
    ],
    targetPlaceholder: "example.com or 1.1.1.1"
  },
  host: {
    name: "Host",
    description: "DNS lookup utility",
    fullGuide: {
      what: "Host is a simple DNS lookup utility that resolves domain names to IP addresses.",
      when: "Use for quick DNS lookups and reverse IP lookups.",
      examples: [
        "host example.com",
        "host 1.1.1.1",
        "host -v example.com (verbose)"
      ],
      risks: "Safe - Simple DNS queries."
    },
    options: [
      { flag: "", label: "Standard Lookup", checked: true },
      { flag: "-v", label: "Verbose", checked: false },
    ],
    targetPlaceholder: "example.com"
  },
  ping: {
    name: "Ping",
    description: "Test host reachability",
    fullGuide: {
      what: "Ping tests host availability and measures round-trip latency using ICMP echo requests.",
      when: "Use for checking if a host is alive and measuring network latency.",
      examples: [
        "ping -c 4 example.com",
        "ping -i 0.2 example.com (fast interval)",
        "ping -W 2 example.com (2 second timeout)"
      ],
      risks: "Safe - Basic network diagnostic tool. Some hosts block ICMP."
    },
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
  const [showOnboarding, setShowOnboarding] = useState(localStorage.getItem("cyber-kit-visited") ? false : true);
  const [showHelp, setShowHelp] = useState(false);
  const terminalRef = useRef(null);

  useEffect(()=>{ refreshJobs(); }, []);

  // Mark onboarding as seen
  const completeOnboarding = () => {
    localStorage.setItem("cyber-kit-visited", "true");
    setShowOnboarding(false);
  };

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

  // Onboarding Modal Component
  const OnboardingModal = () => {
    return (
      <div style={{
        position: "fixed",
        top: 0, left: 0, right: 0, bottom: 0,
        backgroundColor: "rgba(0,0,0,0.85)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        zIndex: 1000
      }}>
        <div style={{
          backgroundColor: "#0d1117",
          border: "1px solid #30363d",
          borderRadius: "8px",
          padding: "32px",
          maxWidth: "600px",
          maxHeight: "80vh",
          overflow: "auto",
          boxShadow: "0 20px 60px rgba(0,0,0,0.9)"
        }}>
          <h1 style={{marginTop: 0, color: "#58a6ff"}}>🎯 Welcome to Cyber Tool Kit!</h1>
          
          <h3>What is this?</h3>
          <p>This is an advanced cybersecurity reconnaissance and testing tool that provides a user-friendly interface for network scanning, DNS enumeration, HTTP testing, and more.</p>

          <h3>📋 Available Tools (8 Tools)</h3>
          <ul style={{fontSize: "14px", lineHeight: "1.8"}}>
            <li><strong>Nmap</strong> - Network scanning, port discovery, service enumeration</li>
            <li><strong>Masscan</strong> - Fast large-scale port scanning</li>
            <li><strong>Whois</strong> - Domain and IP registrant information</li>
            <li><strong>Dig</strong> - DNS lookup and zone enumeration</li>
            <li><strong>Curl</strong> - HTTP requests and web server testing</li>
            <li><strong>Traceroute</strong> - Network path analysis</li>
            <li><strong>Host</strong> - Simple DNS resolution</li>
            <li><strong>Ping</strong> - Host availability and latency testing</li>
          </ul>

          <h3>⚠️ Important Legal Notice</h3>
          <div style={{
            backgroundColor: "#161b22",
            border: "1px solid #f85149",
            padding: "12px",
            borderRadius: "4px",
            fontSize: "13px",
            marginBottom: "16px"
          }}>
            <strong style={{color: "#f85149"}}>⚠️ WARNING:</strong><br/>
            Only use this tool on networks and systems you own or have explicit written permission to test. Unauthorized security testing is illegal in most jurisdictions. You are responsible for your actions.
          </div>

          <h3>🚀 How to Get Started</h3>
          <ol style={{fontSize: "14px", lineHeight: "1.8"}}>
            <li>Select a tool from the dropdown</li>
            <li>Enter your target (domain, IP, CIDR range)</li>
            <li>Choose options using the checkboxes OR edit the args manually</li>
            <li>Click "▶️ Run" to execute the scan</li>
            <li>View live output in the terminal below</li>
            <li>Click "❓ Help & Guide" for detailed info about each tool</li>
          </ol>

          <h3>💡 Pro Tips</h3>
          <ul style={{fontSize: "13px", lineHeight: "1.6"}}>
            <li>Checkboxes auto-build command-line arguments</li>
            <li>You can override/edit arguments in the "Custom Arguments" field</li>
            <li>Recent job results appear in the sidebar</li>
            <li>Each tool has its own set of optimized options</li>
            <li>Click "❓ Help & Guide" button for tool-specific guides</li>
          </ul>

          <div style={{marginTop: "24px", display: "flex", gap: "12px"}}>
            <button 
              className="button btn-primary" 
              onClick={completeOnboarding}
              style={{flex: 1}}
            >
              ✅ Got it! Let me start
            </button>
            <button 
              className="button btn-ghost" 
              onClick={() => { completeOnboarding(); setShowHelp(true); }}
              style={{flex: 1}}
            >
              📚 Show Tool Guide
            </button>
          </div>
        </div>
      </div>
    );
  };

  // Help Panel Component
  const HelpPanel = () => {
    const toolDef = TOOL_OPTIONS[tool];
    if (!toolDef || !toolDef.fullGuide) return null;

    const guide = toolDef.fullGuide;

    return (
      <div style={{
        position: "fixed",
        top: 0, left: 0, right: 0, bottom: 0,
        backgroundColor: "rgba(0,0,0,0.85)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        zIndex: 1000
      }}>
        <div style={{
          backgroundColor: "#0d1117",
          border: "1px solid #30363d",
          borderRadius: "8px",
          padding: "32px",
          maxWidth: "700px",
          maxHeight: "85vh",
          overflow: "auto",
          boxShadow: "0 20px 60px rgba(0,0,0,0.9)"
        }}>
          <div style={{display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "20px"}}>
            <h2 style={{marginTop: 0, color: "#58a6ff"}}>{toolDef.name} — Complete Guide</h2>
            <button 
              className="button btn-ghost" 
              onClick={() => setShowHelp(false)}
              style={{padding: "4px 8px", fontSize: "14px"}}
            >
              ✕ Close
            </button>
          </div>

          <div style={{borderBottom: "1px solid #30363d", paddingBottom: "16px", marginBottom: "16px"}}>
            <p><strong>📝 Description:</strong> {toolDef.description}</p>
          </div>

          <div style={{marginBottom: "16px"}}>
            <h4 style={{color: "#79c0ff"}}>❓ What does it do?</h4>
            <p>{guide.what}</p>
          </div>

          <div style={{marginBottom: "16px"}}>
            <h4 style={{color: "#79c0ff"}}>⏰ When to use it</h4>
            <p>{guide.when}</p>
          </div>

          <div style={{marginBottom: "16px"}}>
            <h4 style={{color: "#79c0ff"}}>📚 Usage Examples</h4>
            <ul style={{backgroundColor: "#161b22", padding: "12px", borderRadius: "4px", fontSize: "12px", fontFamily: "monospace", color: "#79c0ff"}}>
              {guide.examples.map((ex, i) => (
                <li key={i} style={{marginBottom: "6px"}}>{ex}</li>
              ))}
            </ul>
          </div>

          <div style={{marginBottom: "16px", backgroundColor: "#161b22", padding: "12px", borderRadius: "4px", borderLeft: "3px solid #f85149"}}>
            <h4 style={{marginTop: 0, color: "#f85149"}}>⚠️ Risk Level & Warnings</h4>
            <p style={{marginBottom: 0}}>{guide.risks}</p>
          </div>

          <div style={{marginTop: "24px", display: "flex", gap: "12px"}}>
            <button 
              className="button btn-primary" 
              onClick={() => setShowHelp(false)}
              style={{flex: 1}}
            >
              ✅ Close
            </button>
            <button 
              className="button btn-ghost" 
              onClick={() => {
                setShowHelp(false);
                // Scroll to options area
                setTimeout(() => {
                  document.querySelector(".tool-options")?.scrollIntoView({ behavior: "smooth" });
                }, 100);
              }}
              style={{flex: 1}}
            >
              ▶️ Go to Tool
            </button>
          </div>
        </div>
      </div>
    );
  };

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
      {showOnboarding && <OnboardingModal />}
      {showHelp && <HelpPanel />}
      
      <div className="card">
        <div style={{display: "flex", justifyContent: "space-between", alignItems: "center"}}>
          <h2 style={{marginTop: 0}}>🛠️ Cyber Tool Kit</h2>
          <div style={{display: "flex", gap: "8px"}}>
            <button 
              className="button btn-ghost" 
              onClick={() => setShowOnboarding(true)}
              title="View onboarding"
              style={{padding: "6px 12px", fontSize: "14px"}}
            >
              ℹ️ Start
            </button>
            <button 
              className="button btn-ghost" 
              onClick={() => setShowHelp(true)}
              title="View detailed tool guides"
              style={{padding: "6px 12px", fontSize: "14px"}}
            >
              ❓ Help & Guide
            </button>
          </div>
        </div>
        
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
              <div className="tool-options">
                <ToolOptionsBuilder tool={tool} onArgsChange={setArgsText} />
              </div>
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
