# AgentAudit — System Overview & Architecture

> Stand: 2026-02-28 | CLI v3.13.5 | Audit Prompt v2 (785 Zeilen)

## 1. Was ist AgentAudit?

AgentAudit ist ein Security-Scanner für AI-Agent-Pakete (MCP Server, Skills, npm/pip). Es nutzt LLMs um Source-Code automatisch auf Sicherheitsprobleme zu prüfen — vergleichbar mit einem statischen Code-Audit, aber mit dem Verständnis eines menschlichen Security-Reviewers.

**Kern-Differenzierung:** Kein Pattern-Matching (wie Semgrep/CodeQL), sondern semantische Analyse durch Frontier-LLMs die den Code "lesen" und verstehen.

---

## 2. Architektur-Überblick

```
┌─────────────────────────────────────────────────────────────┐
│                        BENUTZER                             │
│                                                             │
│  CLI (npx agentaudit)    Website (agentaudit.dev)           │
│  Skill (Claude Code)     GitHub Action (CI/CD)              │
│  MCP Server (Query API)                                     │
└────────┬────────────────────┬──────────────────────────────-┘
         │                    │
         ▼                    ▼
┌─────────────────┐  ┌──────────────────┐
│   LLM Analyse   │  │   Registry API   │
│                  │  │   (Next.js)      │
│ ┌──────────────┐ │  │                  │
│ │ Audit Prompt │ │  │  ┌────────────┐  │
│ │ (785 Zeilen) │ │  │  │ Supabase   │  │
│ └──────┬───────┘ │  │  │ PostgreSQL │  │
│        │         │  │  └────────────┘  │
│        ▼         │  │                  │
│ ┌──────────────┐ │  │  Reports         │
│ │ OpenRouter   │ │  │  Findings        │
│ │ (Multi-LLM)  │ │  │  Scores          │
│ └──────────────┘ │  │  Reviews         │
└─────────────────┘  └──────────────────┘
```

### Kernkomponenten

| Komponente | Beschreibung | Ort |
|-----------|-------------|-----|
| **CLI** (`cli.mjs`) | 6.476 Zeilen JS, Haupttool. `npx agentaudit audit <url>` | `agentaudit-cli` Repo |
| **Audit Prompt** | 785 Zeilen, 3-Phasen-Analyse. Das Herzstück. | `prompts/audit-prompt.md` |
| **Web App** | Next.js 14, Registry UI, Free Scan, Profile | `agentaudit-web` Repo |
| **Registry API** | REST API, Reports speichern/abfragen, Trust Scores | `agentaudit-web/src/app/api/` |
| **Skill** | SKILL.md für Claude Code, Auto-Check vor `npm install` | `agentaudit-skill` Repo |
| **MCP Server** | MCP-Abfrage-Tool für die Registry | `agentaudit-mcp` Repo |
| **GitHub Action** | CI/CD Security Gate | `agentaudit-github-action` Repo |

---

## 3. Der Audit-Flow (Schritt für Schritt)

### 3.1 Eingabe

```bash
agentaudit audit https://github.com/user/mcp-server
```

### 3.2 Repository klonen & Dateien sammeln

1. `git clone --depth 1` ins Temp-Verzeichnis
2. Dateien sammeln: `.js`, `.ts`, `.py`, `.go`, `.rs`, `.json`, `.yml`, `.md`, etc.
3. Binaries, `node_modules`, `.git` werden ausgeschlossen
4. Max ~82 relevante Dateien pro Scan

### 3.3 Payload vorbereiten

- Package-Info extrahieren (Name, Version aus `package.json`/`pyproject.toml`)
- Audit Prompt (785 Zeilen System Prompt) + alle Dateien als User Message
- Context-Limit prüfen: >90% = Warnung, >100% = Abbruch

### 3.4 LLM-Analyse (3-Pass)

Der Audit Prompt instruiert das LLM, drei Phasen nacheinander zu durchlaufen:

**PHASE 1 — UNDERSTAND:**
- Alle Dateien lesen
- Package Profile erstellen (Name, Purpose, Category, Package Type)
- Trust Boundaries identifizieren
- Expected vs. Abnormal Behaviors definieren

**PHASE 2 — DETECT:**
- Checkliste abarbeiten (Network, Filesystem, Execution, Obfuscation, etc.)
- 11 Severity-Patterns prüfen (CRITICAL bis INFORMATIONAL)
- MCP-spezifische Prüfungen (Tool Arguments = UNTRUSTED!)
- Devil's Advocate: Für jede Nicht-Finding argumentieren, WARUM es ein Risiko sein KÖNNTE

**PHASE 3 — CLASSIFY:**
- Findings nach Schwere einordnen
- Self-Check gegen 10-Punkte-Liste
- False Positive Elimination
- JSON-Report generieren

### 3.5 Post-Processing (`enrichFindings()`)

Das LLM-Ergebnis wird deterministisch nachbearbeitet:
- CWE-IDs zuweisen (basierend auf Pattern-Matching, nicht LLM)
- Code-Snippets extrahieren
- Remediation-Vorschläge ergänzen
- Package-Version aus Manifest
- Risk Score berechnen (Backend, nicht LLM)

### 3.6 Optional: Verification Pass (Pass 2)

```bash
agentaudit audit <url> --verify self    # Same model verifies
agentaudit audit <url> --verify cross   # Different model verifies
```

Für jedes Finding aus Pass 1:
- 5-Punkte-Checkliste gegen den echten Code:
  1. Existiert der Code?
  2. Stimmt der Kontext?
  3. Passt die Severity?
  4. Ist das Execution Model korrekt?
  5. Wurde etwas fabricated?
- Verdicts: `verified` / `demoted` (Severity runter) / `rejected` (entfernt)

### 3.7 Upload & Reporting

- Report wird an `agentaudit.dev/api/reports` geschickt
- Risk Score: Backend berechnet (CRITICAL -25, HIGH -15, MEDIUM -5, LOW -1)
- Trust Score: 100 - Risk Score (Minimum 0)
- Lokale History: `~/.config/agentaudit/history/`

---

## 4. Der Audit Prompt — Das Herzstück

### 4.1 Struktur (785 Zeilen)

```
§1   — Phase 1: UNDERSTAND (Package Profile, Trust Boundaries)
§2   — Phase 2: DETECT (Checkliste, Severity Patterns)
§3   — Triage Rules (die kritischsten Regeln)
  §3.1 — Self-Check (10 Fragen)
  §3.2 — Negative Examples (20+ False Positive Muster)
  §3.3 — Core-Functionality-Exemption
  §3.4 — Opt-In Rule
  §3.5 — MCP Trust Boundary Rule ← NEU (Session 16)
  §3.6 — Calibration Examples (TP + FP Beispiele)
  §3.7 — Devil's Advocate
  §3.8 — Reasoning Chain
  §3.9 — Severity Assignment
  §3.10 — By-Design Classification
  §3.11 — Final Triage
§4   — Phase 3: CLASSIFY (JSON Schema)
```

### 4.2 Kritische Design-Entscheidungen

**MCP Trust Boundary Rule (§3.5):**
> In MCP Servern sind ALLE Tool-Arguments vom LLM/Client UNTRUSTED Input.

Das ist die wichtigste Erkenntnis aus Session 16. Vor diesem Fix behandelten alle Models MCP-Tool-Arguments als "interne" Daten und flaggten keine fehlende Input-Validierung.

**Feature vs. Implementation Flaw:**
- "Server schreibt Dateien" → `by_design` (Feature)
- "Server schreibt Dateien ohne Path-Validierung" → `PATH_TRAV` (Bug)

**Self-Check Q1 (präzisiert):**
> Ist das die dokumentierte Kernfunktionalität UND validiert die Implementierung ihre Inputs?
> → Nur wenn BEIDES zutrifft: at most LOW/by_design

### 4.3 Prompt-Wartung

Der Prompt existiert an **5 Stellen** und muss synchron gehalten werden:
1. `agentaudit-cli/prompts/audit-prompt.md` (Quelle der Wahrheit)
2. `agentaudit-web/src/app/api/scan/route.ts` (inline)
3. `agentaudit-skill/` (inline in SKILL.md-Payload)
4. `agentaudit-mcp/` (inline)
5. `prompts/verification-prompt.md` (Verification Pass)

---

## 5. Multi-Model Consensus

### 5.1 Konzept

Kein einzelnes LLM findet alles. Verschiedene Models haben verschiedene Stärken:
- Opus 4.6: Beste Präzision, findet subtile Bugs
- Gemini 3.1 Pro: Gründlichste Analyse, findet am meisten
- Grok 4: Aggressiver, findet Edge Cases
- Sonnet 4.6: Gute Balance zwischen Precision und Recall

### 5.2 Aktuelles Lineup (4 Models)

| Model | Provider | Context | Kosten (in/out) | Stärke |
|-------|----------|---------|-----------------|--------|
| Claude Opus 4.6 | Anthropic | 200K | $5/$25 | Höchste Präzision |
| Claude Sonnet 4.6 | Anthropic | 200K | $3/$15 | Bestes Preis-Leistung |
| Grok 4 | xAI | 256K | $3/$15 | Komplementäre Erkennung |
| Gemini 3.1 Pro | Google | 1M | $2/$12 | Tiefste Analyse |

### 5.3 Disqualifizierte Models

| Model | Problem |
|-------|---------|
| **GPT-4.1** | Gibt nur 97 Output-Tokens aus bei großen Codebases. Analysiert den Code nicht. |
| **GPT-4o** | 128K Context zu klein für die meisten Repos (86-108K Tokens Audit) |
| **DeepSeek** | 64K Context viel zu klein |

### 5.4 Wie Consensus funktioniert

```bash
agentaudit consensus <package-name>   # Zeigt alle Reports aller Models
agentaudit audit <url> --models opus,sonnet,grok,gemini  # Multi-Model Audit
```

Ein Finding gilt als bestätigt, wenn ≥2 unabhängige Models es finden.
Die Findings werden nach Overlap gewichtet: Solo-Findings bekommen niedrigere Confidence.

---

## 6. Real-World Benchmark-Ergebnisse (Session 16)

### 6.1 True Positive Detection

Getestet gegen Packages mit manuell bestätigten Vulnerabilities:

**chrome-devtools-mcp** (3 bestätigte TPs: File Write, Extension Install, TLS):

| Model | File Write | Ext Install | TLS | Total |
|-------|-----------|-------------|-----|-------|
| Opus 4.6 | ✅ MEDIUM | ✅ MEDIUM | ✅ LOW | **3/3** |
| Sonnet 4.6 | ✅ HIGH | ✅ MEDIUM | ✅ LOW | **3/3** |
| Gemini 3.1 Pro | ✅ HIGH | ✅ HIGH | - | **2/3** + bonus (temp path, CI binary) |
| Grok 4 | ✅ HIGH | ❌ | ❌ | **1/3** + FPs |
| GPT-4.1 | ❌ | ❌ | ❌ | **0/3** |

**terraform-mcp-server** (2 bestätigte TPs: TLS Bypass, Unverified Binary):

| Model | TLS Bypass | Binary DL | Total |
|-------|-----------|-----------|-------|
| Opus 4.6 | ✅ MEDIUM | ✅ MEDIUM | **2/2** |
| Sonnet 4.6 | ✅ MEDIUM | ❌ | **1/2** |
| Gemini 3.1 Pro | (truncated) | (truncated) | N/A |
| Grok 4 | ✅ HIGH | ✅ HIGH | **2/2** + 2 FPs |
| GPT-4.1 | ❌ | ❌ | **0/2** |

### 6.2 False Positive Control

Getestet gegen saubere Packages (supabase-mcp, qdrant, playwright-mcp, inspector):
- Alle 4 Models: **0 False Positives** auf bestätigt sauberen Packages
- anthropic-cookbook: 1 Finding (pickle.load — fragwürdig, aber nicht unberechtigt)

### 6.3 CVE-Abdeckung (aktuelle Versionen)

Pakete mit gefixten CVEs korrekt als "clean" erkannt:
- playwright-mcp (CVE-2025-9611 gefixt) → SAFE ✅
- MCP Inspector (CVE-2025-49596 gefixt) → SAFE ✅
- mcp-remote (CVE-2025-6514 gefixt) → SAFE + 2 kleinere Issues ✅

---

## 7. Erkenntnisse aus Sessions 12-16

### 7.1 Die Prompt-Über-Härtung (Session 16 — KRITISCH)

**Problem:** Der Audit Prompt wurde für Gemini FP-Reduktion gehärtet. Dies tötete den Recall für ALLE Models.

**Symptom:** Alle 5 Frontier-Models verpassten bestätigte True Positives.

**Ursache:** 6 Recall-Killer im Prompt:
1. Self-Check Q1 war ein Kill-Switch ("core functionality → NOT a finding")
2. Core-Functionality-Exemption zu breit
3. Fehlende MCP Trust Boundary Rule
4. Opt-In Rule zu breit
5. Unvollständige Ausnahmeliste
6. Massive FP-Bias in Beispielen

**Fix:** 5 gezielte Prompt-Änderungen (siehe §4.2 oben)

**Lektion:** NIEMALS model-spezifische Prompt-Fixes. Ein Prompt für alle Models. Testen, testen, testen.

### 7.2 GPT-4.1 "Lazy Output" (Session 16)

**Problem:** GPT-4.1 gibt bei großen Codebases nur 97 Output-Tokens aus — analysiert den Code gar nicht.

**Beweis:** Funktioniert mit 1 Datei (findet Vuln), versagt bei 82 Dateien.

**Konsequenz:** GPT-4.1 aus Consensus-Lineup entfernt. OpenAI-Models generell ungeeignet.

### 7.3 Context-Limit Bug (Session 16)

**Problem:** `gpt-4.1` matched auf `gpt-4` (8K Limit) statt eigenem 1M Eintrag.

**Ursache:** Unsortierte Key-Lookup: `"gpt-4.1".includes("gpt-4")` → true

**Fix:** Length-sorted Keys (längster Match zuerst) + neue Model-Einträge

### 7.4 Verification Pass (Session 14-15)

**Problem:** ~70% False Positive Rate bei Erstscans (v.a. Gemini).

**Lösung:** Zweiter Pass der jedes Finding gegen den echten Code verifiziert.
- 5-Punkte-Checkliste (Code-Existenz, Kontext, Severity, Execution Model, Fabrication)
- Verdicts: verified / demoted / rejected
- Reduziert FP-Rate auf ~30% (stricte Definition) bzw. ~5% (nach Verification)

### 7.5 Real-World vs. Synthetische Benchmarks (Session 16)

**Problem:** Synthetische Benchmarks überschätzen die Genauigkeit.

| Metrik | Benchmark | Real-World |
|--------|-----------|------------|
| Precision | 83% | 30% (strikt) / 73% (lenient) |
| CRITICAL TP Rate | N/A | 0% |
| Hallucinations | ~0% | 5.4% |
| Overstated Severity | ~17% | 42.9% |

**Lektion:** Nur Real-World Daten vertrauen. Synthetische Tests sind notwendig aber nicht ausreichend.

### 7.6 Model-Kontext-Limits (Session 16)

MCP Server Audits benötigen 86K-108K Tokens. Das eliminiert:
- GPT-4o (128K → zu knapp nach Prompt-Overhead)
- DeepSeek (64K → zu klein)
- Mistral Small (32K → viel zu klein)

Nur Models mit ≥200K Context sind geeignet.

---

## 8. Trust Score & Risk Score

### Berechnung (Backend, NICHT LLM)

```
Risk Score = Σ (severity_weights)
  CRITICAL: -25
  HIGH:     -15
  MEDIUM:   -5
  LOW:      -1

Trust Score = max(0, 100 - Risk Score)

Recovery: Wenn Finding als "fixed" markiert → +50% des Abzugs zurück
```

### Badges

| Score | Badge | Farbe |
|-------|-------|-------|
| 0-5 | SAFE | Grün |
| 6-20 | LOW | Gelb-Grün |
| 21-40 | CAUTION | Gelb |
| 41-60 | UNSAFE | Orange |
| 61-100 | CRITICAL | Rot |

---

## 9. Offene Punkte & Nächste Schritte

### Sofort (Session 16)
- [ ] Prompt an alle 5 Stellen synchronisieren
- [ ] `google/gemini-3.1-pro-preview` als korrekten OpenRouter Model-Namen dokumentieren
- [ ] FP-Regression auf Top 20 Packages validieren
- [ ] npm publish v3.13.6 mit allen Fixes
- [ ] Benchmark-Daten in agentaudit-benchmarks committen

### Mittelfristig
- [ ] Gemini Output-Truncation beheben (max_tokens erhöhen oder Code chunken)
- [ ] Real-World CVE Benchmark Suite aufbauen (15 bestätigte CVEs identifiziert)
- [ ] `agentaudit watch` — FS-Watcher für MCP Config-Änderungen
- [ ] Blog: "State of MCP Security 2026"
- [ ] Vercel Auto-Deploy fixen (Webhook nach Org-Transfer verloren)

### Langfristig
- [ ] 5. Model im Lineup finden (OpenAI disqualifiziert, DeepSeek zu klein)
- [ ] Incremental Scans (nur geänderte Dateien, Git-Diff-basiert)
- [ ] Custom Severity Rules (User-konfigurierbar)

---

## 10. Glossar

| Begriff | Bedeutung |
|---------|-----------|
| **ASF-ID** | AgentAudit Security Finding ID (z.B. `ASF-2025-0001`) |
| **Trust Score** | 0-100, 100 = keine bekannten Issues |
| **Risk Score** | 0-100, Summe der Finding-Gewichte |
| **Consensus** | Multi-Model Bestätigung eines Findings |
| **Verification Pass** | Zweiter LLM-Pass der Findings gegen Code prüft |
| **by_design** | Finding ist erwartetes Verhalten, keine Vuln |
| **PATH_TRAV** | Path Traversal — unsanitized File-Pfade |
| **CMD_INJ** | Command Injection |
| **SEC_BYPASS** | Security Bypass |
| **MCP Trust Boundary** | Alle Tool-Arguments = UNTRUSTED Input |
