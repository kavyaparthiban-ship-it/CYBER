import { useCallback, useEffect, useState } from "react";

const API = "/api";

async function request(path, options) {
  const response = await fetch(`${API}${path}`, { credentials: "same-origin", ...options });
  const type = response.headers.get("content-type") || "";
  const body = type.includes("application/json") ? await response.json() : null;
  if (!response.ok) {
    if (response.status === 401 && !path.startsWith("/auth/")) {
      window.dispatchEvent(new Event("hackgrid:unauthorized"));
    }
    const error = new Error(body?.detail || `Request failed (${response.status})`);
    error.status = response.status;
    throw error;
  }
  return body;
}

function Icon({ name }) {
  const paths = {
    grid: <><rect x="3" y="3" width="7" height="7" rx="1" /><rect x="14" y="3" width="7" height="7" rx="1" /><rect x="3" y="14" width="7" height="7" rx="1" /><rect x="14" y="14" width="7" height="7" rx="1" /></>,
    scan: <><circle cx="11" cy="11" r="7" /><path d="m20 20-4-4M11 7v4l3 2" /></>,
    history: <><path d="M3 12a9 9 0 1 0 3-6.7L3 8" /><path d="M3 3v5h5m4-1v5l3 2" /></>,
    shield: <><path d="M12 22s8-4 8-11V5l-8-3-8 3v6c0 7 8 11 8 11Z" /><path d="m9 12 2 2 4-4" /></>,
    upload: <><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" /><path d="m17 8-5-5-5 5M12 3v12" /></>,
    download: <><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" /><path d="m7 10 5 5 5-5M12 15V3" /></>,
    file: <><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" /><path d="M14 2v6h6M8 13h8m-8 4h8" /></>,
    arrow: <><path d="M7 17 17 7M7 7h10v10" /></>,
  };
  return <svg className="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{paths[name]}</svg>;
}

function Metric({ label, value, note, tone }) {
  return <article className="metric card">
    <div className={`metric-mark ${tone || ""}`} />
    <div className="metric-label">{label}</div>
    <div className="metric-value">{value ?? "—"}</div>
    <div className="metric-note">{note}</div>
  </article>;
}

function Status({ value }) {
  return <span className={`badge ${String(value).toLowerCase()}`}>{value}</span>;
}

function AuthScreen({ onAuthenticated, initialError = "" }) {
  const [mode, setMode] = useState("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState(initialError);
  const [busy, setBusy] = useState(false);

  const submit = async (event) => {
    event.preventDefault();
    setError("");
    if (mode === "signup" && password.length < 10) {
      setError("Choose a password with at least 10 characters.");
      return;
    }
    if (mode === "signup" && password !== confirmPassword) {
      setError("The passwords do not match.");
      return;
    }
    setBusy(true);
    try {
      const { user } = await request(`/auth/${mode === "signup" ? "signup" : "login"}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
      });
      onAuthenticated(user);
    } catch (cause) {
      setError(cause.message);
    } finally {
      setBusy(false);
    }
  };

  return <main className="auth-page">
    <div className="auth-shell">
      <section className="auth-welcome">
        <a className="brand auth-brand" href="#" onClick={(event) => event.preventDefault()}>
          <span className="brand-mark"><span /></span>
          <span><strong>HACKGRID</strong><small>IPsec security analyzer</small></span>
        </a>
        <div className="auth-copy">
          <div className="auth-eyebrow"><span className="live-indicator" /> SECURE ANALYSIS WORKSPACE</div>
          <h1>Clarity for your <span>encrypted</span> network.</h1>
          <p>Inspect IPsec captures, surface configuration risks, and turn packet metadata into a clearer security picture.</p>
        </div>
        <div className="auth-art" aria-hidden="true">
          <div className="auth-orbit orbit-one" /><div className="auth-orbit orbit-two" />
          <div className="auth-core"><span className="brand-mark"><span /></span></div>
          <i className="orbit-node node-one" /><i className="orbit-node node-two" /><i className="orbit-node node-three" />
          <div className="art-caption"><span>SIH26160</span><i /> IPSEC PROTOCOL ANALYSIS</div>
        </div>
        <div className="auth-footer"><span>SMART INDIA HACKATHON 2026</span><span>TEAM 126281 <i /> HACKGRID</span></div>
      </section>

      <section className="auth-panel-wrap">
        <div className="auth-card card">
          <div className="auth-card-kicker"><span className="section-kicker">LOCAL ANALYST WORKSPACE</span><Status value="PoC" /></div>
          <h2>{mode === "login" ? "Welcome back" : "Create your account"}</h2>
          <p className="auth-intro">{mode === "login" ? "Sign in to continue to your security dashboard." : "Set up a local account to get started with HACKGRID."}</p>
          <div className="auth-tabs" role="tablist" aria-label="Account options">
            <button type="button" role="tab" aria-selected={mode === "login"} className={mode === "login" ? "active" : ""} onClick={() => { setMode("login"); setError(""); }}>Sign in</button>
            <button type="button" role="tab" aria-selected={mode === "signup"} className={mode === "signup" ? "active" : ""} onClick={() => { setMode("signup"); setError(""); }}>Create account</button>
          </div>
          <form className="auth-form" onSubmit={submit}>
            <label htmlFor="auth-email">Email address</label>
            <input id="auth-email" type="email" autoComplete="email" placeholder="analyst@example.com" value={email} onChange={(event) => setEmail(event.target.value)} required maxLength={254} />
            <div className="auth-password-label"><label htmlFor="auth-password">Password</label>{mode === "signup" && <span>10+ CHARACTERS</span>}</div>
            <input id="auth-password" type="password" autoComplete={mode === "signup" ? "new-password" : "current-password"} placeholder={mode === "signup" ? "Create a strong password" : "Enter your password"} value={password} onChange={(event) => setPassword(event.target.value)} required minLength={mode === "signup" ? 10 : 1} maxLength={128} />
            {mode === "signup" && <>
              <label htmlFor="auth-confirm">Confirm password</label>
              <input id="auth-confirm" type="password" autoComplete="new-password" placeholder="Re-enter your password" value={confirmPassword} onChange={(event) => setConfirmPassword(event.target.value)} required maxLength={128} />
            </>}
            {error && <div className="auth-error" role="alert"><span>!</span>{error}</div>}
            <button type="submit" className="button primary auth-submit" disabled={busy}>
              {busy ? "Please wait…" : mode === "login" ? "Sign in to workspace" : "Create local account"} <span>→</span>
            </button>
          </form>
          <div className="auth-divider"><span /></div>
          <div className="auth-assurance"><span className="auth-lock"><Icon name="shield" /></span><p><b>Your workspace, kept local.</b><br />Account details are stored in this app's local SQLite database. This PoC is not a production identity service.</p></div>
        </div>
        <div className="auth-bottom">OFFLINE-FIRST PCAP ANALYSIS <i /> NO PAYLOAD DECRYPTION</div>
      </section>
    </div>
  </main>;
}

function App() {
  const [user, setUser] = useState(null);
  const [authReady, setAuthReady] = useState(false);
  const [authError, setAuthError] = useState("");
  const [view, setView] = useState("Overview");
  const [analysis, setAnalysis] = useState(null);
  const [history, setHistory] = useState([]);
  const [stats, setStats] = useState(null);
  const [file, setFile] = useState(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [dragging, setDragging] = useState(false);
  const [filter, setFilter] = useState("ALL");
  const [health, setHealth] = useState("checking");

  const refresh = useCallback(async () => {
    try {
      const [healthData, historyData, statsData] = await Promise.all([
        request("/health"), request("/analysis/history"), request("/dashboard/statistics"),
      ]);
      setHealth(healthData.status);
      setHistory(historyData);
      setStats(statsData);
    } catch {
      setHealth("offline");
    }
  }, []);

  useEffect(() => {
    let active = true;
    request("/auth/me")
      .then(({ user: currentUser }) => { if (active) setUser(currentUser); })
      .catch((cause) => { if (active && cause.status !== 401) setAuthError("The local API is unavailable. Start the application again and retry."); })
      .finally(() => { if (active) setAuthReady(true); });
    return () => { active = false; };
  }, []);

  useEffect(() => {
    if (user) refresh();
  }, [user, refresh]);

  useEffect(() => {
    const handleUnauthorized = () => {
      setUser(null);
      setAuthError("Your session expired. Please sign in again.");
    };
    window.addEventListener("hackgrid:unauthorized", handleUnauthorized);
    return () => window.removeEventListener("hackgrid:unauthorized", handleUnauthorized);
  }, []);

  const signOut = async () => {
    try {
      await request("/auth/logout", { method: "POST" });
    } catch {
      setAuthError("Signed out locally; the server could not confirm session cleanup.");
    } finally {
      setUser(null);
      setAnalysis(null);
      setView("Overview");
    }
  };

  if (!authReady) {
    return <main className="auth-page"><div className="auth-loading card"><span className="brand-mark"><span /></span><strong>HACKGRID</strong><span>Connecting to your local workspace…</span></div></main>;
  }
  if (!user) {
    return <AuthScreen initialError={authError} onAuthenticated={(authenticatedUser) => { setAuthError(""); setUser(authenticatedUser); }} />;
  }

  const acceptFile = (candidate) => {
    setError("");
    setAnalysis(null);
    if (!candidate) return;
    if (!candidate.name.toLowerCase().endsWith(".pcap")) {
      setFile(candidate);
      setError("PCAPNG and other file extensions are not supported. Select a classic .pcap capture.");
      return;
    }
    if (candidate.size === 0) {
      setFile(candidate);
      setError("The selected file is empty.");
      return;
    }
    if (candidate.size > 20 * 1024 * 1024) {
      setFile(candidate);
      setError("The capture exceeds the 20 MB upload limit.");
      return;
    }
    setFile(candidate);
  };

  const analyze = async (demo = false) => {
    setError("");
    if (!demo && !file) {
      setError("Choose a .pcap file first, or analyze the clearly labelled synthetic demo capture.");
      return;
    }
    setBusy(true);
    try {
      const result = demo
        ? await request("/analyze/demo", { method: "POST" })
        : await request(`/analyze?filename=${encodeURIComponent(file.name)}`, {
          method: "POST",
          headers: { "Content-Type": "application/vnd.tcpdump.pcap" },
          body: file,
        });
      setAnalysis(result);
      setView("Overview");
      await refresh();
      document.getElementById("results")?.scrollIntoView({ behavior: "smooth", block: "start" });
    } catch (cause) {
      setError(cause.message);
    } finally {
      setBusy(false);
    }
  };

  const openHistory = async (id) => {
    setError("");
    try {
      setAnalysis(await request(`/analysis/${id}`));
      setView("Overview");
      window.scrollTo({ top: 0, behavior: "smooth" });
    } catch (cause) {
      setError(cause.message);
    }
  };

  const downloadSample = async () => {
    try {
      const response = await fetch(`${API}/sample`);
      if (!response.ok) throw new Error(`Sample download failed (${response.status})`);
      const blob = await response.blob();
      const href = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = href;
      link.download = "HACKGRID_DEMO_DATA_synthetic.pcap";
      link.click();
      URL.revokeObjectURL(href);
    } catch (cause) {
      setError(cause.message);
    }
  };

  const findings = analysis?.assessment?.findings || [];
  const visibleFindings = filter === "ALL" ? findings : findings.filter((item) => item.status === filter);

  const capture = analysis?.capture;
  const maxProtocol = capture ? Math.max(capture.ike_count, capture.esp_count, capture.ah_count, 1) : 1;

  return <div className="shell">
    <aside className="sidebar">
      <a className="brand" href="#" onClick={() => setView("Overview")}>
        <span className="brand-mark"><span /></span>
        <span><strong>HACKGRID</strong><small>IPsec security analyzer</small></span>
      </a>
      <div className="side-label">WORKSPACE</div>
      <nav className="nav-list" aria-label="Main navigation">
        {[
          ["Overview", "grid"],
          ["PCAP analysis", "scan"],
          ["Analysis history", "history"],
          ["Limitations", "shield"],
        ].map(([label, icon]) => <button key={label} className={`nav-item ${view === label ? "selected" : ""}`} onClick={() => setView(label)}>
          <Icon name={icon} /><span>{label}</span>{label === "PCAP analysis" && <span className="nav-dot" />}
        </button>)}
      </nav>
      <div className="sidebar-spacer" />
      <div className="sidebar-note">
        <div className="note-icon"><Icon name="shield" /></div>
        <div className="note-title">Offline-first analysis</div>
        <p>Captures are processed locally by this PoC. No live network monitoring.</p>
        <span className={`connection ${health === "ok" ? "online" : ""}`}><i /> API {health === "ok" ? "connected" : health}</span>
      </div>
      <div className="side-footer">SIH 2026 <span>·</span> PHASE 3 PoC</div>
    </aside>

    <main className="main">
      <header className="topbar">
        <div className="breadcrumb">Security operations <span>/</span> <b>{view}</b></div>
        <div className="top-status"><span className="live-indicator" /> LOCAL LAB <span className="divider" /> SIH26160 <span className="divider" /><span className="signed-in-email">{user.email}</span><button className="signout-button" onClick={signOut}>Sign out</button></div>
      </header>

      <div className="page-wrap">
        <section className="page-heading">
          <div>
            <div className="eyebrow"><span className="eyebrow-line" /> SMART INDIA HACKATHON 2026 <span className="eyebrow-sep">/</span> TEAM 126281</div>
            <h1>{view === "Analysis history" ? "Analysis history" : view === "Limitations" ? "Scope & limitations" : "IPsec security overview"}</h1>
            <p className="subtitle">AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework</p>
          </div>
          <div className="heading-tag"><span>H</span> HACKGRID</div>
        </section>

        {view === "Limitations" ? <section className="card limitations">
          <div className="section-title"><div><span className="section-kicker">TRANSPARENCY</span><h2>Implemented scope</h2></div><Status value="PoC" /></div>
          <p className="muted">This interface reports only what the local packet parser observes. An unknown setting is never treated as a pass or a failure.</p>
          <ul className="limit-list">
            <li><b>Implemented:</b> offline classic PCAP v2.4 parsing for Ethernet and raw IP; IPv4/IPv6 packet protocol identification; IKE headers and selected IKEv2 SA_INIT transforms; ESP/AH SPI and sequence headers.</li>
            <li><b>Implemented:</b> deterministic demonstration rules, SQLite analysis history, risk score, and downloadable PDF report.</li>
            <li><b>Not implemented:</b> trained ML classifier or confidence score; live packet capture; PCAPNG support; payload decryption; blockchain; PostgreSQL.</li>
            <li><b>Interpret carefully:</b> observed IKE transforms are proposals/offers, not proof of negotiated settings. Findings are a limited PoC ruleset, not a compliance certification.</li>
            <li><b>Demo data:</b> the built-in capture is generated synthetic lab data using documentation-only IP addresses. It is not a real VPN capture.</li>
          </ul>
        </section> : view === "Analysis history" ? <section className="card history-card">
          <div className="section-title"><div><span className="section-kicker">LOCAL SQLITE</span><h2>Previous analyses</h2></div><span className="muted">{history.length} stored</span></div>
          <HistoryTable history={history} openHistory={openHistory} />
        </section> : <>
          <section className="metrics-grid">
            <Metric label="Analysis sessions" value={stats?.analyses ?? "—"} note="Stored in local SQLite" tone="blue" />
            <Metric label="Packets processed" value={capture?.packet_count ?? stats?.packets ?? "—"} note={analysis ? "Current capture" : "Across saved analyses"} tone="cyan" />
            <Metric label="IPsec packets" value={capture ? capture.ike_count + capture.esp_count + capture.ah_count : (stats ? stats.ike + stats.esp + stats.ah : "—")} note={capture ? "IKE + ESP + AH" : "Across saved analyses"} tone="green" />
            <Metric label="Elevated risk scans" value={stats?.elevated ?? "—"} note="HIGH / CRITICAL assessments" tone="amber" />
          </section>

          <section className="workspace-grid" id="analysis">
            <article className="card upload-card">
              <div className="section-title">
                <div><span className="section-kicker">OFFLINE PCAP INSPECTION</span><h2>Analyze a capture</h2></div>
                <span className="offline-pill"><i /> OFFLINE</span>
              </div>
              <div
                className={`dropzone ${dragging ? "dragging" : ""} ${file ? "has-file" : ""}`}
                onDragOver={(event) => { event.preventDefault(); setDragging(true); }}
                onDragLeave={() => setDragging(false)}
                onDrop={(event) => { event.preventDefault(); setDragging(false); acceptFile(event.dataTransfer.files[0]); }}
              >
                <input aria-label="Select classic PCAP capture" type="file" accept=".pcap,application/vnd.tcpdump.pcap" onChange={(event) => acceptFile(event.target.files[0])} />
                <div className="upload-icon"><Icon name="upload" /></div>
                <strong>{file ? file.name : "Drop a PCAP file here"}</strong>
                <span>{file ? `${(file.size / 1024).toFixed(1)} KB · ${file.name.toLowerCase().endsWith(".pcap") ? "classic PCAP" : "unsupported format"}` : "or click to browse your files"}</span>
                {!file && <div className="format-hint">CLASSIC PCAP · ETHERNET / RAW IP · MAX 20 MB</div>}
              </div>
              <div className="upload-actions">
                <button className="button primary" disabled={busy || !file || !!error} onClick={() => analyze(false)}>
                  <Icon name="scan" /> {busy ? "Analyzing capture…" : "Analyze capture"}
                </button>
                <button className="button secondary" disabled={busy} onClick={() => analyze(true)}>Analyze demo data</button>
              </div>
              <div className="sample-row">
                <div className="sample-badge">DEMO</div>
                <p><b>Synthetic lab capture.</b> Generated locally; not real network traffic.</p>
                <button className="text-button" onClick={downloadSample}><Icon name="download" /> Download PCAP</button>
              </div>
              {error && <div className="error-box" role="alert"><span className="error-symbol">!</span><div><b>Analysis could not continue</b><p>{error}</p></div><button aria-label="Dismiss error" onClick={() => setError("")}>×</button></div>}
            </article>

            <article className={`card risk-card ${analysis ? "risk-ready" : ""}`}>
              <div className="section-title"><div><span className="section-kicker">CURRENT ASSESSMENT</span><h2>Risk overview</h2></div><span className="risk-shield"><Icon name="shield" /></span></div>
              {analysis ? <>
                <div className="risk-score-row"><div className="risk-score">{analysis.assessment.score}<small>/100</small></div><Status value={analysis.assessment.category} /></div>
                <div className="risk-track"><span style={{ width: `${analysis.assessment.score}%` }} className={analysis.assessment.category.toLowerCase()} /></div>
                <p className="risk-formula">{analysis.assessment.formula}</p>
                <div className="risk-summary">
                  <div><span>FAIL</span><b>{analysis.assessment.findings.filter((item) => item.status === "FAIL").length}</b></div>
                  <div><span>WARNING</span><b>{analysis.assessment.findings.filter((item) => item.status === "WARNING").length}</b></div>
                  <div><span>UNKNOWN</span><b>{analysis.assessment.findings.filter((item) => item.status === "UNKNOWN").length}</b></div>
                </div>
              </> : <div className="empty-risk"><div className="empty-shield"><Icon name="shield" /></div><b>Awaiting packet analysis</b><p>Run a capture to calculate a reproducible score from observed findings.</p></div>}
              <div className="risk-foot"><span>Rule-based assessment</span><span className="not-ml">NOT AI / ML</span></div>
            </article>
          </section>

          {analysis && <section className="results-section" id="results">
            <div className="results-heading">
              <div><span className="section-kicker">ANALYSIS RESULT {analysis.demo && <span className="demo-label">· SYNTHETIC DEMO DATA</span>}</span><h2>{analysis.filename}</h2><p>{new Date(analysis.created_at).toLocaleString()} <span>·</span> {analysis.processing_ms} ms measured processing time</p></div>
              <a className="button secondary report-button" href={`${API}/analysis/${analysis.id}/report`}><Icon name="file" /> Download PDF report</a>
            </div>

            <div className="capture-metrics">
              <Metric label="Packets processed" value={capture.packet_count} note={`${capture.other_ip_count} other IP · ${capture.malformed_packets} malformed`} tone="blue" />
              <Metric label="IKE detected" value={capture.ike_count} note="UDP / 500 or NAT-T / 4500" tone="cyan" />
              <Metric label="ESP detected" value={capture.esp_count} note="Protocol 50 / NAT-T metadata" tone="green" />
              <Metric label="AH detected" value={capture.ah_count} note="Protocol 51" tone="amber" />
            </div>

            <div className="detail-grid">
              <article className="card panel">
                <div className="section-title"><div><span className="section-kicker">OBSERVED TRAFFIC</span><h2>Protocol distribution</h2></div><span className="muted">{capture.packet_count} packets</span></div>
                <div className="bar-chart">
                  {[["IKE", capture.ike_count, "bar-blue"], ["ESP", capture.esp_count, "bar-cyan"], ["AH", capture.ah_count, "bar-green"], ["Other IP", capture.other_ip_count, "bar-gray"]].map(([label, value, tone]) =>
                    <div className="bar-row" key={label}><span>{label}</span><div className="bar-track"><i className={tone} style={{ width: `${Math.max(value ? 4 : 0, (value / Math.max(capture.packet_count, 1)) * 100)}%` }} /></div><b>{value}</b></div>)}
                </div>
                <div className="chart-caption">Counts measured from parsed packets. No payload decryption.</div>
              </article>

              <article className="card panel">
                <div className="section-title"><div><span className="section-kicker">IKEV2 SA_INIT</span><h2>Observed transforms</h2></div><span className="proposal-tag">OFFERED</span></div>
                {capture.transforms.length ? <div className="transform-list">{capture.transforms.map((item, index) =>
                  <div className="transform-row" key={`${item.type}-${item.id}-${index}`}><span className="transform-type">{item.type.replace("_", " ")}</span><span>{item.name}</span><small>ID {item.id}</small></div>)}</div> :
                  <p className="muted no-data">No IKEv2 SA_INIT transform payload was observed. Values are not inferred.</p>}
                <div className="chart-caption">Proposal contents are offers, not proof of negotiation.</div>
              </article>
            </div>

            <article className="card panel matrix-panel">
              <div className="section-title matrix-heading"><div><span className="section-kicker">RULE-BASED · OBSERVED METADATA ONLY</span><h2>Security assessment</h2></div>
                <div className="matrix-controls"><label htmlFor="finding-filter">Filter</label><select id="finding-filter" value={filter} onChange={(event) => setFilter(event.target.value)}>{["ALL", "FAIL", "WARNING", "PASS", "UNKNOWN"].map((item) => <option key={item}>{item}</option>)}</select></div>
              </div>
              <div className="table-scroll"><table><thead><tr><th>PARAMETER</th><th>OBSERVED</th><th>STATUS</th><th>REASON &amp; RECOMMENDATION</th><th>RISK</th></tr></thead>
                <tbody>{visibleFindings.map((item) => <tr key={item.id}>
                  <td><b>{item.parameter}</b><small>{item.id}</small></td>
                  <td>{item.observed}</td>
                  <td><Status value={item.status} /></td>
                  <td><span>{item.reason}</span><small className="recommendation">Recommendation: {item.recommendation}</small></td>
                  <td><span className={`risk-contribution ${item.risk_contribution ? "weighted" : ""}`}>+{item.risk_contribution}</span></td>
                </tr>)}</tbody>
              </table>{visibleFindings.length === 0 && <p className="muted no-data">No findings match this filter.</p>}</div>
              <div className="table-foot">UNKNOWN parameters contribute zero risk and are never treated as PASS. This limited ruleset is not a compliance certification.</div>
            </article>

            <div className="detail-grid bottom-grid">
              <article className="card panel">
                <div className="section-title"><div><span className="section-kicker">CLASSIFICATION</span><h2>Encrypted traffic ML</h2></div><Status value="NOT IMPLEMENTED" /></div>
                <p className="muted">No trained model or representative labelled dataset is available. The application does not produce traffic labels, accuracy claims, or confidence scores.</p>
              </article>
              <article className="card panel">
                <div className="section-title"><div><span className="section-kicker">PACKET METADATA</span><h2>ESP / AH headers</h2></div><span className="muted">{capture.esp_packets.length + capture.ah_packets.length} observed</span></div>
                <div className="header-metadata">
                  {[...capture.esp_packets.map((item) => ({ ...item, type: "ESP" })), ...capture.ah_packets.map((item) => ({ ...item, type: "AH" }))].slice(0, 6).map((item, index) =>
                    <div className="header-row" key={`${item.type}-${item.spi}-${index}`}><b>{item.type}</b><span>SPI {item.spi}</span><span>SEQ {item.sequence}</span></div>)}
                  {capture.esp_packets.length + capture.ah_packets.length === 0 && <p className="muted">No ESP/AH headers observed.</p>}
                </div>
                <div className="chart-caption">Sequence and SPI are observed; protected payloads remain encrypted.</div>
              </article>
            </div>
          </section>}

          {!analysis && <section className="card history-preview">
            <div className="section-title"><div><span className="section-kicker">LOCAL SQLITE</span><h2>Recent analyses</h2></div><button className="text-button" onClick={() => setView("Analysis history")}>View history <Icon name="arrow" /></button></div>
            {history.length ? <HistoryTable history={history.slice(0, 5)} openHistory={openHistory} /> :
              <div className="history-empty"><div className="history-file"><Icon name="file" /></div><div><b>No analyses yet</b><p>Choose a capture or run the synthetic demo to populate this workspace.</p></div></div>}
          </section>}
        </>}
        <footer className="footer"><span>HACKGRID <i /> SIH26160 <i /> TEAM 126281</span><span>Offline PCAP PoC <i /> No payload decryption</span></footer>
      </div>
    </main>
  </div>;
}

function HistoryTable({ history, openHistory }) {
  return <div className="table-scroll"><table><thead><tr><th>INPUT</th><th>DATE / TIME</th><th>PACKETS</th><th>IKE / ESP / AH</th><th>RISK</th><th></th></tr></thead>
    <tbody>{history.map((item) => <tr key={item.id}>
      <td><b>{item.filename}</b>{item.demo ? <small className="demo-label">SYNTHETIC DEMO DATA</small> : null}</td>
      <td>{new Date(item.created_at).toLocaleString()}</td><td>{item.packet_count}</td>
      <td>{item.ike_count} / {item.esp_count} / {item.ah_count}</td><td><Status value={item.risk_category} /></td>
      <td><button className="text-button" onClick={() => openHistory(item.id)}>Open <Icon name="arrow" /></button></td>
    </tr>)}</tbody></table>
    {!history.length && <p className="muted no-data">No saved analyses.</p>}
  </div>;
}

export default App;
