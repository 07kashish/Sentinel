#!/usr/bin/env python3
"""Build the Sentinel product dossier PDF (docs/current/Sentinel-Product-Dossier.pdf).

    pip install reportlab          # not a service dependency; needed only to rebuild the PDF
    python scripts/build_dossier.py docs/current/Sentinel-Product-Dossier.pdf "$(git rev-parse --short HEAD)"

The content is WRITTEN HERE, by hand, from docs/current at the commit named on
the cover: it is not generated from the code and does not update itself. When
RELEASE_STATUS.md, COMPETITIVE_MATRIX.md, the test counts or the links change,
edit this file and rebuild, or the PDF will be confidently out of date.
"""
import sys
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (Flowable, KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table,
                                TableStyle)

OUT, COMMIT = sys.argv[1], sys.argv[2]
W, H = A4
INK, MUTED, RULE = colors.HexColor("#14171f"), colors.HexColor("#5b6272"), colors.HexColor("#d5d9e2")
ACCENT, SOFT = colors.HexColor("#c2410c"), colors.HexColor("#f4f5f8")
GOOD, WARN, BAD = colors.HexColor("#0b6b3a"), colors.HexColor("#9a5b00"), colors.HexColor("#a11d1d")
BLUE, BLUEBG = colors.HexColor("#1d4ed8"), colors.HexColor("#eef3ff")

ss = getSampleStyleSheet()
def style(name, **kw):
    base = kw.pop("parent", ss["Normal"])
    return ParagraphStyle(name, parent=base, **kw)
BODY = style("body", fontName="Helvetica", fontSize=9.6, leading=13.6, textColor=INK, spaceAfter=6)
SMALL = style("small", parent=BODY, fontSize=8.2, leading=11, textColor=MUTED)
CELL = style("cell", parent=BODY, fontSize=8.1, leading=10.6, spaceAfter=0)
CELLB = style("cellb", parent=CELL, fontName="Helvetica-Bold")
HEAD = style("head", parent=CELL, fontName="Helvetica-Bold", textColor=colors.white)
H1 = style("h1", fontName="Helvetica-Bold", fontSize=18, leading=22, textColor=INK, spaceBefore=4, spaceAfter=10)
H2 = style("h2", fontName="Helvetica-Bold", fontSize=12.5, leading=16, textColor=ACCENT, spaceBefore=12, spaceAfter=6, keepWithNext=1)
H3 = style("h3", fontName="Helvetica-Bold", fontSize=10.2, leading=13, textColor=INK, spaceBefore=8, spaceAfter=3, keepWithNext=1)
CODE = style("code", fontName="Courier", fontSize=8, leading=10.6, textColor=INK, backColor=SOFT, borderPadding=(5, 6, 5, 6),
             spaceBefore=4, spaceAfter=9, leftIndent=2)
NOTE = style("note", parent=BODY, fontSize=8.8, leading=12.2, backColor=colors.HexColor("#fff7ed"), borderColor=ACCENT,
             borderWidth=0.6, borderPadding=(6, 7, 6, 7), spaceBefore=6, spaceAfter=10)

def P(text, st=BODY): return Paragraph(text, st)
def bullets(items, st=BODY):
    return [Paragraph("&bull;&nbsp;&nbsp;" + i, style("b", parent=st, leftIndent=12, firstLineIndent=-9, spaceAfter=3)) for i in items]
def code(text): return Paragraph(text.replace("&", "&amp;").replace("<", "&lt;").replace("\n", "<br/>").replace("  ", "&nbsp;&nbsp;"), CODE)

def table(rows, widths, header=True, zebra=True, font=CELL):
    data = []
    for r, row in enumerate(rows):
        data.append([c if isinstance(c, Flowable) else Paragraph(str(c), HEAD if header and r == 0 else font) for c in row])
    t = Table(data, colWidths=[w * mm for w in widths], repeatRows=1 if header else 0)
    st = [("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 5), ("RIGHTPADDING", (0, 0), (-1, -1), 5),
          ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4), ("LINEBELOW", (0, 0), (-1, -1), 0.4, RULE),
          ("BOX", (0, 0), (-1, -1), 0.5, RULE)]
    if header: st.append(("BACKGROUND", (0, 0), (-1, 0), INK))
    if zebra:
        for i in range(2 if header else 1, len(rows), 2): st.append(("BACKGROUND", (0, i), (-1, i), SOFT))
    t.setStyle(TableStyle(st))
    return t

class Diagram(Flowable):
    """Boxes and arrows. boxes: (x, y, w, h, title, subtitle, fill). arrows: (x1, y1, x2, y2, label)."""
    def __init__(self, width, height, boxes, arrows, zones=()):
        super().__init__(); self.width, self.height, self.boxes, self.arrows, self.zones = width, height, boxes, arrows, zones
    def wrap(self, *_): return self.width, self.height
    def draw(self):
        c = self.canv
        for x, y, w, h, label in self.zones:
            c.setStrokeColor(RULE); c.setFillColor(colors.HexColor("#fafbfc")); c.setDash(3, 2)
            c.roundRect(x, y, w, h, 6, stroke=1, fill=1); c.setDash()
            c.setFillColor(MUTED); c.setFont("Helvetica-Bold", 7); c.drawString(x + 6, y + h - 10, label.upper())
        for x1, y1, x2, y2, label in self.arrows:
            c.setStrokeColor(MUTED); c.setFillColor(MUTED); c.setLineWidth(0.9); c.line(x1, y1, x2, y2)
            import math
            a = math.atan2(y2 - y1, x2 - x1); s = 5
            p = c.beginPath(); p.moveTo(x2, y2)
            p.lineTo(x2 - s * math.cos(a - 0.4), y2 - s * math.sin(a - 0.4)); p.lineTo(x2 - s * math.cos(a + 0.4), y2 - s * math.sin(a + 0.4)); p.close()
            c.drawPath(p, stroke=0, fill=1)
            if label:
                c.setFont("Helvetica", 6.6); c.setFillColor(INK)
                c.drawCentredString((x1 + x2) / 2, (y1 + y2) / 2 + 4, label)
        for x, y, w, h, title, sub, fill in self.boxes:
            c.setFillColor(fill); c.setStrokeColor(INK); c.setLineWidth(0.7); c.roundRect(x, y, w, h, 4, stroke=1, fill=1)
            c.setFillColor(INK); c.setFont("Helvetica-Bold", 7.6); c.drawCentredString(x + w / 2, y + h - 11, title)
            c.setFont("Helvetica", 6.4); c.setFillColor(MUTED)
            for i, line in enumerate(sub.split("\n")): c.drawCentredString(x + w / 2, y + h - 20 - i * 7.6, line)

def footer(canvas, doc):
    canvas.saveState(); canvas.setFont("Helvetica", 7.5); canvas.setFillColor(MUTED)
    canvas.drawString(18 * mm, 10 * mm, f"Sentinel product dossier  |  commit {COMMIT}  |  invite-only developer preview")
    canvas.drawRightString(W - 18 * mm, 10 * mm, f"{doc.page}"); canvas.setStrokeColor(RULE); canvas.line(18 * mm, 13.5 * mm, W - 18 * mm, 13.5 * mm)
    canvas.restoreState()

S = []
# ───────────────────────── cover ─────────────────────────
S += [Spacer(1, 46 * mm), P("SENTINEL", style("c0", fontName="Helvetica-Bold", fontSize=13, textColor=ACCENT, leading=16)),
      P("Runtime trust for AI agents", style("c1", fontName="Helvetica-Bold", fontSize=30, leading=35, textColor=INK, spaceAfter=10)),
      P("Product dossier: what it does, how it is built, how to set it up and run it, what is proven, and where it stands against the alternatives.",
        style("c2", parent=BODY, fontSize=12.5, leading=17, textColor=MUTED)), Spacer(1, 14 * mm),
      table([["Status", "Invite-only developer preview. Demonstrated on one cloud host. No customer in production."],
             ["Date / commit", f"4 October 2026  |  {COMMIT} (branch program/production-readiness)"],
             ["Live read-only demo", "http://sentinel-proof-557842222.ap-south-1.elb.amazonaws.com/console"],
             ["Windows download", "https://sentinel-downloads-024330900387.s3.ap-south-1.amazonaws.com/downloads/windows/Sentinel-AI-Scan-Windows.exe"],
             ["Evidence", "4,567 automated tests, 0 failures, on SQLite and PostgreSQL; 18 CI jobs green on main"]],
            [38, 136], header=False, zebra=False), Spacer(1, 10 * mm),
      P("<b>How to read this document.</b> Every capability here is tagged with how far it has been proven. The words "
        "<i>production-ready, secure, compliant</i> and <i>market-leading</i> do not appear as claims, because the evidence for them does not "
        "exist yet. Where Sentinel is behind an alternative, this document says so in the same table that says where it is ahead.", NOTE),
      PageBreak()]

# ───────────────────────── 1 what it does ─────────────────────────
S += [P("1. What Sentinel does", H1),
      P("AI agents no longer only answer questions; they change things: they deploy code, edit infrastructure, move money, send messages. "
        "Sentinel is the checkpoint between an agent and the change. Before an agent's tool call takes effect, Sentinel decides one of four "
        "things, by fixed rules rather than by a model's opinion:"),
      table([["Decision", "Meaning", "What happens next"],
             ["allow", "Policy permits the action", "The agent proceeds; an authorization is issued that commits to the exact parameters"],
             ["warn", "Permitted, but noteworthy", "Proceeds and is recorded for review"],
             ["require_approval", "A person must decide", "A request appears in the console with a countdown; nothing runs until someone with the right role approves"],
             ["block", "Policy refuses", "The action does not run; an incident may be raised"]], [30, 44, 100]),
      P("Around that decision Sentinel does six further jobs:", BODY)]
S += bullets([
    "<b>Binds the approval to the execution.</b> An approval commits to a digest of the exact tool, resource and arguments. Different arguments are refused; the same approval cannot run twice.",
    "<b>Records proof.</b> Each execution produces a receipt stating what was approved and what ran. Receipts are committed to a per-tenant transparency log and can be verified offline.",
    "<b>Detects suspicious chains.</b> Events from agents are assembled into incidents (for example: read a file, compress it, post it to an outside host) with the causal chain shown.",
    "<b>Contains an agent.</b> An analyst can pause one agent, with a reason and an expiry; its calls are refused until the containment ends.",
    "<b>Inventories AI tools.</b> A consent-based scanner (command line or a double-click app for macOS and Windows) lists which AI tools are installed on a device.",
    "<b>Adds an advisory second opinion.</b> A model (the owner's Antigravity CLI running Gemini) writes a note for the analyst on each incident. It is labelled unverified and cannot change any decision.",
])
S += [P("What Sentinel is not", H2)]
S += bullets([
    "It is <b>not</b> a SOC or a general AI-security scanner. It governs agent actions; it does not hunt malware or watch a network.",
    "It does <b>not</b> stop an agent that bypasses it. It controls calls routed through it (SDK, tool gateway, MCP proxy). Closing the bypass is a deployment task: credentials the agent does not hold, and network or API-server rules.",
    "It does <b>not</b> let a model decide. Decisions are deterministic policy. Remove the advisor and every decision is identical.",
    "The device scanner sees <b>presence only</b>: that a file, app or command with a known name exists. It opens nothing, runs nothing and sends nothing.",
])
S.append(PageBreak())

# ───────────────────────── 2 how it works ─────────────────────────
S += [P("2. How a protected action flows", H1),
      P("The diagram shows the path of one consequential action, from the agent's request to the proof that it happened as approved.")]
bw, bh = 74, 40
flow = Diagram(170 * mm, 70 * mm,
    boxes=[(0, 150, bw, bh, "AI agent", "wants to change\nsomething", BLUEBG), (102, 150, bw, bh, "SDK / gateway", "check(tool, resource,\narguments)", SOFT),
           (204, 150, bw, bh, "Policy gate", "deterministic rules\n+ tenant policy", colors.HexColor("#fff1e6")),
           (306, 150, bw, bh, "Authorization", "digest of exact\nparameters, expiry", SOFT), (408, 150, bw, bh, "Human approver", "console: reason,\nApprove / Reject", BLUEBG),
           (0, 60, bw, bh, "Incident + note", "chain of events;\nadvisor is advisory", colors.HexColor("#f6f0ff")),
           (102, 60, bw, bh, "Execute proxy", "recomputes digest,\nsingle-use nonce", SOFT), (204, 60, bw, bh, "Target system", "Kubernetes, GitHub,\nAWS, any tool", BLUEBG),
           (306, 60, bw, bh, "Receipt", "approved vs executed,\nsigned", SOFT), (408, 60, bw, bh, "Transparency log", "per tenant,\noffline verifiable", colors.HexColor("#eaf7ef"))],
    arrows=[(74, 170, 102, 170, "ask"), (176, 170, 204, 170, "evaluate"), (278, 170, 306, 170, "decide"), (380, 170, 408, 170, "human?"),
            (343, 150, 139, 100, "approved authorization"), (176, 80, 204, 80, "once"), (278, 80, 306, 80, ""), (380, 80, 408, 80, ""),
            (214, 150, 60, 100, "block / detection")])
S += [flow, Spacer(1, 6),
      table([["Step", "What happens", "What is refused"],
             ["1. Ask", "The agent (through the SDK, the tool gateway or the MCP proxy) asks before acting.", "A caller with no valid key gets no decision at all (401), never an allow."],
             ["2. Decide", "Rules are evaluated on the tool, resource and the actual arguments. Trust comes from how the caller authenticated, not from what it claims.", "A request that asserts its own trust level is rejected."],
             ["3. Authorize", "On allow or require_approval an authorization is stored, bound to tenant, agent, tool, action, resource, parameter digest, policy version, expiry and a single-use nonce.", "An approval for one tenant, agent or policy version cannot be used for another."],
             ["4. Approve", "A person with the decide role reads why approval is needed, types a reason and approves. A quorum and requester/approver separation can be required.", "An expired request (about five minutes) cannot be approved; the agent must ask again."],
             ["5. Execute", "The proxy recomputes the parameter digest immediately before the tool runs.", "Changed arguments, a second use, or execution before approval: all 403."],
             ["6. Prove", "A receipt records the binding. If the target's answer is lost, the operation is marked unknown and reconciled from the target, not repeated.", "A receipt is never silently rewritten; the log is append-only."]],
            [22, 92, 60]),
      PageBreak()]

# ───────────────────────── 3 architecture ─────────────────────────
S += [P("3. Architecture", H1), P("3.1 Deployed architecture (the AWS environment behind the live demo)", H2)]
arch = Diagram(170 * mm, 96 * mm,
    zones=[(92, 34, 388, 196, "AWS account, region ap-south-1 (Mumbai), private network"), (0, 34, 82, 196, "Outside")],
    boxes=[(6, 176, 70, 36, "Browser", "operator console\n(read-only demo)", BLUEBG), (6, 122, 70, 36, "AI agents", "SDK, MCP hosts,\nagent frameworks", BLUEBG),
           (6, 60, 70, 44, "Laptops", "Sentinel AI Scan\n(Mac, Windows)\nreport imported", BLUEBG),
           (104, 150, 70, 46, "Load balancer", "ALB + WAF\nTLS when a\ncertificate is set", colors.HexColor("#fff1e6")),
           (196, 150, 84, 46, "API tasks (x2)", "Fargate, read-only root,\nnon-root; API + console;\nqueue work, run none", SOFT),
           (302, 150, 84, 46, "Brain host", "EC2, no public address;\ndrains the work queue;\nadvisor CLI (agy)", colors.HexColor("#f6f0ff")),
           (400, 156, 72, 34, "Gemini", "via the owner's\nsigned-in CLI", BLUEBG),
           (104, 62, 78, 46, "PostgreSQL", "RDS; forced row-level\nsecurity per tenant;\nencrypted", colors.HexColor("#eaf7ef")),
           (196, 62, 70, 46, "Redis", "shared rate limit\nand readiness\ncache", colors.HexColor("#eaf7ef")),
           (280, 62, 84, 46, "Evidence bucket", "S3, object lock;\ntransparency roots", colors.HexColor("#eaf7ef")),
           (378, 62, 94, 46, "Secrets + KMS", "API keys, DSN, data key;\ninjected at start,\nnever in the image", colors.HexColor("#eaf7ef"))],
    arrows=[(76, 194, 104, 180, "HTTPS"), (76, 140, 104, 166, "API key"), (174, 173, 196, 173, ""), (280, 173, 302, 173, ""),
            (386, 173, 400, 173, ""), (238, 150, 150, 108, ""), (238, 150, 231, 108, ""), (344, 150, 322, 108, ""), (344, 150, 420, 108, ""),
            (238, 150, 410, 108, "")])
S += [arch,
      P("Two API tasks answer every request and serve the console. They run <b>no</b> incident pipeline. One separate host, reachable only through AWS Session "
        "Manager, runs the same image as the pipeline worker with the advisor CLI mounted read-only. The database enforces tenant isolation itself: every "
        "tenant table has forced row-level security, so a query without a tenant context returns nothing.", BODY),
      P("3.2 Code architecture", H2),
      P("The service is one Python package arranged as ports and adapters. Dependencies point inward only; an architecture test fails the build if a layer "
        "imports the wrong way, if any module exceeds 800 lines, or if anything outside the settings module reads the environment."),
      table([["Layer", "Files", "Responsibility", "May depend on"],
             ["domain", "53", "Incidents, authorizations, policy, severity, state machines. Pure logic, no I/O.", "nothing"],
             ["application", "30", "Use cases: admit an event, evaluate, decide an approval, run the pipeline, queries. Defines ports.", "domain"],
             ["infrastructure", "108", "Adapters: SQL (SQLite and PostgreSQL), outbound HTTP hardening, evidence, transparency, SIEM/SOAR, identity, advisor.", "application, domain"],
             ["interface", "29", "HTTP routes, console, CLI, workers, rate limiting.", "application"],
             ["composition", "18", "Settings (170 documented variables), container wiring, production preflight.", "all, at the edge"],
             ["sdk", "14", "Client, framework adapters, MCP stdio bridge, device scanner and desktop app (standard library only).", "nothing server-side"]],
            [28, 14, 96, 36]),
      KeepTogether([P("3.3 Data and state", H2),
      table([["Store", "Holds", "Protection"],
             ["PostgreSQL (schema version 38)", "Incidents, authorizations, approvals, receipts, policy versions, audit trail, work queue, device inventory", "Forced row-level security; the service connects as a non-superuser; migrations are a separate deployment step and the service refuses to start on an old schema"],
             ["Transparency log", "One append-only Merkle log per tenant committing each receipt", "Never reaped; consistency proofs; roots can be published to object-locked storage"],
             ["Evidence bodies", "The detail behind each incident and approval", "Sealed per record under a data key; losing the key loses bodies, never proofs"],
             ["Redis", "Rate-limit counters, readiness cache", "The service refuses to run more than one process in production without it"],
             ["Secrets Manager", "API keys, database URL, data key, demo key", "Injected at task start; not visible in the task definition"]],
            [40, 70, 64])]),
      PageBreak()]

# ───────────────────────── 4 components ─────────────────────────
S += [P("4. Every component, small to large", H1),
      P("Tier is the strongest evidence that exists for the component: <b>integration</b> = passed on PostgreSQL as well as SQLite; <b>unit</b> = passed in tests "
        "only; <b>live</b> = additionally exercised on the AWS environment or a real machine. No component has production or independent-assessment evidence.")]
comp = [["Component", "What it does", "Proven to", "Honest limit"],
    ["Policy gate", "Deterministic rules plus a tenant policy that can only tighten the baseline", "unit; live", "Rules are curated; no outside evaluation of what they miss"],
    ["Execution binding", "Authorization bound to tenant, agent, tool, action, resource, parameter digest, policy digest, expiry, nonce", "integration; live", "Bypass prevention needs the agent to hold no direct credential"],
    ["Approvals", "Redacted change view, quorum, separation of duties, stale-approval refusal, expiry", "integration; live", "Console and API only; no mobile or chat approval"],
    ["Execution proxy + receipts", "Runs the tool once under the approval and records approved-versus-executed", "integration; live", "Commitment to the log is asynchronous"],
    ["Durable outcomes", "A lost response becomes an unknown operation that is reconciled from the target, not retried blindly", "integration", "Automatic for Kubernetes, GitHub contents and brokered AWS only"],
    ["Transparency + passport", "Per-tenant Merkle log; exported bundle verifies offline with the standard library", "integration", "No root is yet held outside the environment"],
    ["Incident pipeline", "Admits events, builds causal chains, triage by severity, evidence, report", "integration; live", "Detection corpus is curated, not blind-tested"],
    ["Advisor", "Model note on each incident via HTTP endpoint or the signed-in Antigravity CLI; sandboxed, no secrets inherited", "unit; live (one host)", "Runs on one personal Google account; 10-60 s per note; unmeasured under load"],
    ["Containment", "Pause an agent, tool or session with reason and expiry", "integration; live", "Only stops calls that pass through Sentinel"],
    ["MCP tool gateway", "Pins tool definitions, detects drift, proxies tools/call under policy", "integration", "Off on the AWS environment; streaming limited; not run against third-party servers"],
    ["A2A gateway", "Agent-card registry and proxy for agent-to-agent calls", "integration", "No real partner agent exercised"],
    ["Workload identity", "Verifies SPIFFE JWT-SVIDs and pod-bound Kubernetes tokens; can refuse API keys for agents", "integration", "Consumes identities; does not issue or rotate them"],
    ["Credential broker", "Per-operation short-lived credentials (Kubernetes TokenRequest, AWS STS, GitHub App)", "integration", "Only the Kubernetes path has met its real service"],
    ["Coverage model", "Counts observed, routed and enforced traffic separately; refuses to invent a percentage", "integration", "Bypass signals need the endpoint sensor deployed"],
    ["Budget + circuit breaker", "Shared, tenant-scoped limits that fail closed", "integration", "Not load-tested beyond two pools"],
    ["Tenant isolation", "Row-level security on PostgreSQL; explicit predicates on SQLite", "integration; live", "Per-pod aggregation and soak unverified"],
    ["SIEM / SOAR export", "Syslog, OTLP, webhook; ServiceNow, Jira, PagerDuty, Slack, Teams connectors", "unit", "No real tenant has consumed it; no vendor certification"],
    ["Retention sweep", "Reaps operational rows per tenant; evidence and receipts are append-only by declaration", "integration", ""],
    ["Console", "13 views: pilot setup, overview, agent requests, approvals, execution graph, approved vs executed, MCP estate, containment, policy, transparency, agents, supply chain, governance", "live", "Operator sign-in refused over plain HTTP by design"],
    ["Python SDK + adapters", "check / execute client; adapters for OpenAI Agents, Anthropic, Gemini, LangChain", "live journey (client)", "Adapters not run against their real frameworks"],
    ["Device scanner", "Presence of 18 AI tools across config files, apps and commands; consent per category", "live (macOS); hosted Windows", "No Windows PC with AI tools installed has been scanned"],
    ["Desktop app", "Double-click window over the scanner for macOS (universal) and Windows", "window smoke on both", "Unsigned: the OS warns on first open"],
    ["Release hygiene", "Allowlisted artifacts, secret scan, hash-pinned lock, clean-install smoke, signed-image option", "unit; CI", "Image signing unverified until publishing is enabled"]]
S += [table(comp, [34, 66, 30, 44]), PageBreak()]

# ───────────────────────── 5 setup ─────────────────────────
S += [P("5. Setting Sentinel up", H1), P("There are three ways to run it today, in increasing effort. None is a production service.")]
S += [P("5.1 Just the scanner (2 minutes, nothing to install)", H2),
      table([["Platform", "Get it", "Run it"],
             ["Windows 10/11 (64-bit)", "Download Sentinel-AI-Scan-Windows.exe from the link on the cover", "Double-click. SmartScreen: More info, then Run anyway. Tick what you agree to check, Scan, Save report."],
             ["macOS (Apple Silicon or Intel)", "Sentinel-AI-Scan-macOS.zip, sent by the owner", "Unzip, right-click the app, Open, Open. Tick, Scan, Save report."],
             ["Any OS with Python 3.9+", "sentinel-discover.py from the console (Pilot setup)", "python3 sentinel-discover.py --consent --all --output me.json --html me.html"]], [42, 62, 70]),
      P("The saved .html page is the readable result; the .json file is what a Sentinel console imports. Nothing is sent anywhere by the scanner.", SMALL),
      P("5.2 Your own Sentinel on a laptop (10 minutes)", H2), P("Needs a copy of the repository and Python 3.12 or newer."),
      P("macOS / Linux", H3), code('python3 -m venv .venv\n.venv/bin/pip install -e ".[server]"\n.venv/bin/python scripts/try_sentinel.py --scan --demo'),
      P("Windows (PowerShell)", H3), code('py -m venv .venv\n.venv\\Scripts\\pip install -e ".[server]"\n.venv\\Scripts\\python scripts\\try_sentinel.py --scan --demo'),
      P("That one command creates a private folder with a database and four fresh keys, prepares the database, scans the device, imports the result, loads a sample "
        "story and serves the console at <b>http://127.0.0.1:8000/console</b>. Paste the printed <b>admin key</b> as the operator token. To approve a request live: "
        "<b>Agent requests</b>, type a reason, <b>Approve</b>. For new waiting requests run the same script with <font face='Courier'>--fresh-requests</font> in a second terminal. "
        "Add <font face='Courier'>--advisor-cli ~/.local/bin/agy --advisor-model gemini-3.1-pro-high</font> to attach the advisor."),
      P("5.3 The cloud environment (what the live demo runs)", H2),
      table([["#", "Step", "Detail"],
             ["1", "AWS identity", "A provisioning role that the operator assumes; credentials stay in an untracked .env"],
             ["2", "Build and push", "Build the container image, push to the environment's registry, pin by digest"],
             ["3", "Apply the stack", "OpenTofu (deploy/terraform/aws): network, load balancer + WAF, two API tasks, PostgreSQL, Redis, evidence storage, secrets, keys, alarms, budgets, backup"],
             ["4", "Set secrets", "Tenant API keys (one per role), database URL, evidence data key; values are put by hand, never in code"],
             ["5", "Migrate", "Run the schema migration as a one-off task. The service refuses to start on an old schema"],
             ["6", "Roll and verify", "Roll the service; a rollout only counts when the running revision is the one requested"],
             ["7", "Brain host (optional)", "Enable the brain host; connect through Session Manager; install the advisor CLI in /opt/agy; sign in once"],
             ["8", "HTTPS", "A certificate for app.joinsentinelai.com is requested; two DNS records at the registrar complete it"]], [8, 34, 132]),
      P("5.4 Roles and keys", H2),
      table([["Role", "Can", "Cannot"],
             ["ingest", "Send events, ask for decisions, execute approved actions", "Read incidents or approve"],
             ["viewer", "Read everything in the console", "Change anything (the public demo key is this role)"],
             ["analyst", "Viewer, plus approve/reject requests and contain agents", "Change policy or users"],
             ["admin", "Analyst, plus policy, users and device inventory imports", ""]], [24, 84, 66]),
      P("\"Operator token\" in the console simply means one of these keys. The tenant is derived from the key, never from the request.", SMALL),
      P("5.5 Settings that matter most", H2),
      table([["Setting", "Effect"],
             ["SENTINEL_PROTECT_ENFORCE, SENTINEL_PROTECTION_MODE", "Whether a stop decision actually stops the action. Without them a verdict is advisory"],
             ["SENTINEL_REQUIRE_EXECUTION_BINDING", "Refuses any execution that does not present an authorization (on by default)"],
             ["SENTINEL_API_KEYS", "tenant:key:role entries. The only way callers are identified in the first workflow"],
             ["SENTINEL_DATABASE_URL / SENTINEL_REDIS_URL", "PostgreSQL and Redis. SQLite and a single process are refused in production"],
             ["SENTINEL_DATA_KEY_&lt;id&gt;, SENTINEL_ACTIVE_KEY_ID", "Seals evidence bodies. Production refuses to start without a key"],
             ["SENTINEL_ADVISOR_CLI_COMMAND + _MODEL (or _ENDPOINT + _MODEL + _TOKEN)", "Attaches the advisory model. All-or-nothing; absent means no advisor, stated in every record"],
             ["SENTINEL_PIPELINE_WORKERS", "Pipeline threads in this process; 0 makes an API-only replica"],
             ["SENTINEL_CONSOLE_DEMO_TOKEN", "Publishes a viewer key on the sign-in page; refused unless that key is viewer-only"]], [70, 104]),
      PageBreak()]

# ───────────────────────── 6 evidence ─────────────────────────
S += [P("6. What is proven, and what is not", H1),
      table([["Evidence", "Result"],
             ["Automated suite, both database engines, including a live Kubernetes contract test", "4,567 tests, 0 failures, 0 errors, 38 skipped (commit 60b5109)"],
             ["GitHub CI on main", "All 18 jobs green: suite, live PostgreSQL/Redis, kind + Helm smoke, security, licences, image build, deployment manifests, release hygiene"],
             ["Live AWS environment", "Console, liveness, readiness 200; viewer refused a decision (403); no key refused (401); new incident carries the advisor note"],
             ["Client SDK against a real server", "Allow, require approval, refused before approval, approve, execute once, replay refused"],
             ["Desktop app", "Real window opened, ticked, scanned on macOS and on a hosted Windows machine"],
             ["Local trial on Windows", "Install, migrate, serve, scan, import, sample story: passed on a hosted Windows machine"]], [86, 88]),
      P("Capability tiers (generated from the test evidence, not written by hand)", H2),
      table([["Tier", "Count", "Meaning"], ["production_observed", "0", "Seen working for a real tenant"], ["externally_verified", "0", "Independently assessed"],
             ["integration_tested", "12", "Passed on PostgreSQL as well as SQLite"], ["unit_tested", "4", "Passed in tests on these exact inputs"]], [44, 18, 112]),
      P("Open risks (from the risk register)", H2),
      table([["Id", "Severity", "Risk", "State"],
             ["R-001", "critical", "No production deployment has observed any control", "open"],
             ["R-002", "high", "No independent security assessment", "open"],
             ["R-003", "high", "Cross-region disaster recovery is unproven", "open"],
             ["R-004", "high", "Cloud topology applied on one host/region only", "mitigated"],
             ["R-005", "medium", "Detection metrics come from a curated corpus only", "open"],
             ["R-012", "medium", "Automatic reconciliation covers three target types; the rest needs a human", "mitigated"]], [16, 20, 112, 26]),
      Spacer(1, 8), P("Not tested in CI today: the live S3-compatible round-trip (the upstream MinIO image was withdrawn). Not done by anyone: a person using the Windows app on a PC "
        "with AI tools installed; code signing of either app; any run of the framework adapters against their real frameworks.", NOTE),
      PageBreak()]

# ───────────────────────── 7 competition ─────────────────────────
S += [P("7. Sentinel and the alternatives", H1),
      P("This comparison is built from each vendor's own public documentation, reviewed 17-20 September 2026. <b>No head-to-head test has been run.</b> "
        "\"Not found in their documentation\" means this review did not find it, not that the product lacks it. Read the \"ahead\" column as "
        "<i>what Sentinel can demonstrate on request</i>, and the \"behind\" column as fact."),
      P("7.1 Where Sentinel is ahead, and where it is behind", H2)]
G = lambda t: Paragraph(f'<font color="#0b6b3a">{t}</font>', CELL)
R = lambda t: Paragraph(f'<font color="#a11d1d">{t}</font>', CELL)
S += [table([["Area", "Sentinel ahead (demonstrable today)", "Sentinel behind (who leads, and why)"],
    ["Exact-change binding", G("Approval commits to a digest of the exact parameters, policy version and a single-use nonce; changed arguments and replays are refused. Shown live."),
     R("AWS AgentCore documents parameter-level Cedar policies; the Agent Permission Protocol draft specifies signed scoped approvals. The idea is not unique.")],
    ["Outcome after a lost response", G("An ambiguous execution becomes an unknown operation and is reconciled from the target without a second write (Kubernetes, GitHub contents, brokered AWS)."),
     R("Only three target types. Nobody, including Sentinel, has shown this at a customer.")],
    ["Proof that survives Sentinel", G("Receipts in a per-tenant transparency log; a bundle verifies offline with no Sentinel software."),
     R("No root is yet held outside the environment, and no restore from an independent failure domain has been done.")],
    ["Honest coverage", G("Reports observed, routed and enforced traffic separately and refuses to turn them into one percentage."),
     R("Bypass detection depends on a sensor being deployed; network egress and non-Kubernetes targets are not covered.")],
    ["Agent identity", G("Consumes SPIFFE and pod-bound Kubernetes identities; can refuse plain API keys for agents."),
     R("Microsoft Entra Agent ID, Auth0, Teleport and SPIRE issue, rotate and govern identities. Sentinel does not, and has not been integrated with any of them.")],
    ["Credential brokering", G("Per-operation short-lived credentials for three targets."),
     R("Auth0 Token Vault, Pomerium and Teleport broker credentials for many upstreams, in production.")],
    ["Approval experience", G("Redacted change view, quorum, separation of duties, expiry."),
     R("ITSM tools and Auth0 asynchronous authorization approve from phone, chat and tickets. Sentinel has a console and an API.")],
    ["Gateway breadth", G("MCP proxy with pinned tool definitions and drift detection."),
     R("Kong AI Gateway and AWS AgentCore run managed gateways at measured scale with full streaming. Sentinel's proxy is off in its own demo.")],
    ["Threat detection", G("Deterministic chain detection with the causal graph shown."),
     R("Palo Alto Prisma AIRS and Check Point / Lakera are dedicated detection products with independent evaluation. Sentinel has none.")],
    ["Device inventory", G("Consent-based presence scan with a double-click app; opens and sends nothing."),
     R("Presence only. No visibility of browser or cloud AI, which endpoint and browser-security vendors cover.")],
    ["Trust and distribution", G("Every claim is tiered by evidence; nothing is overstated."),
     R("Every funded competitor has customers, assessments, attestations, marketplaces and support. Sentinel has none of these.")]],
    [30, 70, 74]),
      P("7.2 Alternative by alternative", H2),
      table([["Alternative", "What its documentation shows", "Sentinel's honest position"],
    ["AWS Bedrock AgentCore (Policy / Gateway)", "Deterministic Cedar authorization at tool invocation, default deny; managed gateway; IAM/OAuth principals", "An integration target. Sentinel must show added approval and outcome value before an AWS-only customer adds it"],
    ["Microsoft Entra Agent ID", "Agent identity lifecycle, ownership and governance", "Integrate with it; Sentinel validates tokens but has no native Entra lifecycle integration"],
    ["Auth0 for AI Agents", "Authentication, Token Vault, asynchronous human authorization, fine-grained authorization", "Human approval alone is not unique. Sentinel's case is precise scope plus independently observed outcome"],
    ["Teleport", "Short-lived cryptographic workload identities and infrastructure access", "Integrate; Sentinel's attestation and credential issuance lack real-workflow evidence"],
    ["Kong AI Gateway", "MCP aggregation, routing, access policy, logging, rate limiting", "Integrate rather than rebuild routing; Sentinel has not measured comparable interoperability or cost"],
    ["Pomerium MCP gateway", "Per-request policy, tool-level access, upstream OAuth and token delegation", "Cannot claim unique delegated MCP access; compare the full protected-change workflow"],
    ["Palo Alto Prisma AIRS", "Runtime API/firewall, model security, red teaming, posture", "No detection or red-team comparison exists; avoid any superiority claim"],
    ["Check Point AI Guardrails / Lakera", "Screens messages, tool interactions and tool descriptions through a Guard API", "Evaluate as an advisory input; Sentinel's detector tests cannot establish better protection"],
    ["Agent Permission Protocol (draft)", "Execution-time policy verification, capability binding, signed approval receipts", "Direct conceptual overlap; pursue interoperability and a narrower observed-outcome advantage"],
    ["Customer-built (IdP + gateway + admission + SIEM)", "Whatever the customer has assembled", "Sentinel must beat their actual integration labour and investigation time, not a weak hypothetical"]],
    [44, 64, 66]),
      P("7.3 The unique selling proposition, stated carefully", H2),
      P("No single feature has been shown to be absent from every alternative, and this document does not claim one. The proposition is the <b>combination, end to end, "
        "with honest failure handling</b>:"),]
S += bullets([
    "<b>The exact change that was approved is the change that ran</b>, and a different or repeated one is refused at the last moment.",
    "<b>When the outcome is uncertain, Sentinel says so</b> and reconciles from the target instead of guessing or repeating.",
    "<b>The proof outlives Sentinel</b>: a receipt bundle that verifies offline.",
    "<b>It tells you where it is not protecting you</b>: observed, routed and enforced are counted separately.",
    "<b>A model never decides</b>: the advisor informs a human and holds no authority.",
])
S += [P("Each of these is a hypothesis until a customer trial compares it with what that customer uses today. The five acceptance tests for doing so are in "
        "USP_VALIDATION.md in the repository.", SMALL), PageBreak()]

# ───────────────────────── 8 launch ─────────────────────────
S += [P("8. From preview to launch", H1),
      P("An <b>invited developer preview</b> is ready today: chosen people get the demo link, the apps and the guide. A public launch is blocked by the items below, in order."),
      table([["#", "Gap", "Why it blocks", "Owner", "Size"],
             ["1", "HTTPS on the console", "Operators cannot sign in; browsers mark the page not secure. Certificate requested for app.joinsentinelai.com; two DNS records outstanding", "Owner", "An hour"],
             ["2", "Apps unsigned", "macOS and Windows warn on first open", "Owner: Apple Developer ID, Windows certificate", "Days"],
             ["3", "Windows app on a real PC with AI tools", "The folder list has only met a machine with none installed", "Any Windows user", "Minutes"],
             ["4", "Terms, privacy notice, sign-up, billing", "Strangers running a scanner need a privacy notice; nobody can become a customer unaided", "Owner", "Days to weeks"],
             ["5", "Operations", "One region, single-zone database, no on-call", "Owner", "Weeks"],
             ["6", "Outside evidence", "No security assessment, no customer, no blind detection corpus", "Owner + third parties", "Weeks to months"],
             ["7", "Advisor on a personal account", "Quota and continuity depend on one person's Google sign-in", "Owner", "Days"]], [8, 38, 76, 32, 20]),
      P("Where things are", H2),
      table([["Item", "Location"],
             ["Live demo (read-only)", "http://sentinel-proof-557842222.ap-south-1.elb.amazonaws.com/console"],
             ["Windows app, checksum, guide", "https://sentinel-downloads-024330900387.s3.ap-south-1.amazonaws.com/downloads/windows/ (Sentinel-AI-Scan-Windows.exe, .sha256, README-Windows.txt)"],
             ["Owner's demo runbook", "docs/current/DEMO_RUNBOOK.md"], ["Tester's guide", "docs/current/TRY_SENTINEL.md"],
             ["Evidence tiers / risks", "docs/current/RELEASE_STATUS.md, RISK_REGISTER.md"],
             ["Competitive sources", "docs/current/COMPETITIVE_MATRIX.md (primary links, access dates)"],
             ["Change history", "docs/current/RELEASE_CHANGES.md"]], [48, 126]),
      Spacer(1, 8), P("The accurate one-line description until items 1, 2 and 4 are done: <b>invite-only developer preview with tested execution control, demonstrated on one cloud host.</b>", NOTE)]

doc = SimpleDocTemplate(OUT, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm, topMargin=16 * mm, bottomMargin=18 * mm,
                        title="Sentinel product dossier", author="Sentinel")
doc.build(S, onFirstPage=footer, onLaterPages=footer)
print("written", OUT)
