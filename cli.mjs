#!/usr/bin/env node
/**
 * AgentAudit CLI — Security scanner for AI packages
 *
 * Usage: agentaudit <command> [options]
 *
 * Commands:
 *   discover              Find MCP servers across all AI tools
 *   scan <url> [url...]   Quick static scan (regex)
 *   audit <url> [url...]  Deep LLM-powered security audit
 *   lookup <name>         Look up package in registry
 *   dashboard             Interactive full-screen dashboard
 *   leaderboard           Top contributors ranking
 *   benchmark             LLM model performance comparison
 *   activity              Your recent audits & findings
 *   search <query>        Search packages in registry
 *   model [name|reset]    Configure LLM provider + model
 *   login                 Sign in with GitHub (opens browser, auto-creates API key)
 *   setup                 Manual login — paste an API key from agentaudit.dev
 *   status                Show current config + auth status
 *   profile               Your profile — rank, points, audit stats
 *   help [command]        Show help
 *
 * Flags: --json, --quiet, --no-color, --no-upload, --model, --export, --format, --debug
 */

import fs from 'fs';
import os from 'os';
import path from 'path';
import crypto from 'crypto';
import { execSync, execFileSync } from 'child_process';
import { createInterface } from 'readline';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SKILL_DIR = path.resolve(__dirname);
const REGISTRY_URL = 'https://agentaudit.dev';

// ── Global error handlers — catch unhandled errors and exit cleanly ────
process.on('uncaughtException', (err) => {
  process.stderr.write(`\nagentaudit: fatal error — ${err.message || err}\n`);
  if (process.argv.includes('--debug')) process.stderr.write(`${err.stack || ''}\n`);
  process.exit(2);
});
process.on('unhandledRejection', (reason) => {
  const msg = reason instanceof Error ? reason.message : String(reason);
  process.stderr.write(`\nagentaudit: unhandled promise rejection — ${msg}\n`);
  if (process.argv.includes('--debug') && reason instanceof Error) process.stderr.write(`${reason.stack || ''}\n`);
  process.exit(2);
});

// ── Global flags (set in main before command routing) ────
let jsonMode = false;
let quietMode = false;

// ── LLM Provider Registry ───────────────────────────────
const LLM_PROVIDERS = [
  // Native APIs (unique formats)
  { key: 'ANTHROPIC_API_KEY',   name: 'Anthropic (Claude)',   provider: 'anthropic',   type: 'anthropic', model: 'claude-sonnet-4-20250514',  url: 'https://api.anthropic.com/v1/messages' },
  { key: 'GEMINI_API_KEY',      name: 'Google (Gemini)',       provider: 'google',      type: 'gemini',    model: 'gemini-2.5-flash',          url: 'https://generativelanguage.googleapis.com/v1beta/models' },
  { key: 'GOOGLE_API_KEY',      name: 'Google (Gemini)',       provider: 'google',      type: 'gemini',    model: 'gemini-2.5-flash',          url: 'https://generativelanguage.googleapis.com/v1beta/models' },
  // OpenAI-compatible APIs
  { key: 'OPENAI_API_KEY',      name: 'OpenAI (GPT-4o)',       provider: 'openai',      type: 'openai',    model: 'gpt-4o',                    url: 'https://api.openai.com/v1/chat/completions' },
  { key: 'DEEPSEEK_API_KEY',    name: 'DeepSeek',              provider: 'deepseek',    type: 'openai',    model: 'deepseek-chat',             url: 'https://api.deepseek.com/v1/chat/completions' },
  { key: 'MISTRAL_API_KEY',     name: 'Mistral',               provider: 'mistral',     type: 'openai',    model: 'mistral-large-latest',      url: 'https://api.mistral.ai/v1/chat/completions' },
  { key: 'GROQ_API_KEY',        name: 'Groq',                  provider: 'groq',        type: 'openai',    model: 'llama-3.3-70b-versatile',   url: 'https://api.groq.com/openai/v1/chat/completions' },
  { key: 'XAI_API_KEY',         name: 'xAI (Grok)',            provider: 'xai',         type: 'openai',    model: 'grok-4',                    url: 'https://api.x.ai/v1/chat/completions' },
  { key: 'TOGETHER_API_KEY',    name: 'Together AI',           provider: 'together',    type: 'openai',    model: 'meta-llama/Llama-3.3-70B-Instruct-Turbo', url: 'https://api.together.xyz/v1/chat/completions' },
  { key: 'FIREWORKS_API_KEY',   name: 'Fireworks AI',          provider: 'fireworks',   type: 'openai',    model: 'accounts/fireworks/models/llama-v3p3-70b-instruct', url: 'https://api.fireworks.ai/inference/v1/chat/completions' },
  { key: 'CEREBRAS_API_KEY',    name: 'Cerebras',              provider: 'cerebras',    type: 'openai',    model: 'llama-3.3-70b',             url: 'https://api.cerebras.ai/v1/chat/completions' },
  { key: 'ZAI_API_KEY',         name: 'Zhipu AI (GLM)',        provider: 'zhipu',       type: 'openai',    model: 'glm-4.7',                   url: 'https://api.z.ai/api/paas/v4/chat/completions' },
  { key: 'ZHIPUAI_API_KEY',     name: 'Zhipu AI (GLM)',        provider: 'zhipu',       type: 'openai',    model: 'glm-4.7',                   url: 'https://api.z.ai/api/paas/v4/chat/completions' },
  // Meta-provider (routes to any model)
  { key: 'OPENROUTER_API_KEY',  name: 'OpenRouter',            provider: 'openrouter',  type: 'openai',    model: 'anthropic/claude-sonnet-4', url: 'https://openrouter.ai/api/v1/chat/completions' },
];

// ── Provider-specific model choices (for interactive menu) ──
const PROVIDER_MODELS = {
  anthropic: [
    { label: 'claude-sonnet-4-20250514', sublabel: 'fast + smart (default)', value: 'claude-sonnet-4-20250514' },
    { label: 'claude-opus-4-20250514',   sublabel: 'best precision (recommended for audits)', value: 'claude-opus-4-20250514' },
  ],
  openai: [
    { label: 'gpt-4o',  sublabel: 'fast multimodal (default)', value: 'gpt-4o' },
    { label: 'gpt-4.1', sublabel: 'large context (low recall on audits)', value: 'gpt-4.1' },
  ],
  google: [
    { label: 'gemini-2.5-flash', sublabel: 'fast + cheap (default)', value: 'gemini-2.5-flash' },
    { label: 'gemini-2.5-pro',   sublabel: 'strong reasoning',      value: 'gemini-2.5-pro' },
    { label: 'gemini-3.1-pro',   sublabel: 'best detection (recommended for audits)', value: 'gemini-3.1-pro' },
  ],
  deepseek: [
    { label: 'deepseek-chat', sublabel: 'cost-effective (default)', value: 'deepseek-chat' },
  ],
  mistral: [
    { label: 'mistral-large-latest', sublabel: 'EU-hosted (default)', value: 'mistral-large-latest' },
  ],
  groq: [
    { label: 'llama-3.3-70b-versatile', sublabel: 'ultra-fast (default)', value: 'llama-3.3-70b-versatile' },
  ],
  xai: [
    { label: 'grok-4', sublabel: 'best detection (default, recommended)', value: 'grok-4' },
    { label: 'grok-3', sublabel: 'faster, lower cost',                    value: 'grok-3' },
  ],
  together: [
    { label: 'meta-llama/Llama-3.3-70B-Instruct-Turbo', sublabel: 'open source (default)', value: 'meta-llama/Llama-3.3-70B-Instruct-Turbo' },
  ],
  fireworks: [
    { label: 'accounts/fireworks/models/llama-v3p3-70b-instruct', sublabel: 'open source (default)', value: 'accounts/fireworks/models/llama-v3p3-70b-instruct' },
  ],
  cerebras: [
    { label: 'llama-3.3-70b', sublabel: 'fast inference (default)', value: 'llama-3.3-70b' },
  ],
  zhipu: [
    { label: 'glm-4.7', sublabel: 'Chinese language (default)', value: 'glm-4.7' },
  ],
  openrouter: [
    { label: 'anthropic/claude-sonnet-4', sublabel: 'default',         value: 'anthropic/claude-sonnet-4' },
    { label: 'qwen/qwen3-coder',          sublabel: 'code specialist', value: 'qwen/qwen3-coder' },
    { label: 'meta-llama/Llama-3.3-70B',  sublabel: 'open source',    value: 'meta-llama/Llama-3.3-70B' },
  ],
};

// ── ANSI Colors (respects NO_COLOR and --no-color) ───────

const noColor = !!(process.env.NO_COLOR || process.argv.includes('--no-color'));

const c = noColor ? {
  reset: '', bold: '', dim: '', red: '', green: '', yellow: '',
  blue: '', magenta: '', cyan: '', white: '', gray: '',
  bgRed: '', bgGreen: '', bgYellow: '',
} : {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  white: '\x1b[37m',
  gray: '\x1b[90m',
  bgRed: '\x1b[41m',
  bgGreen: '\x1b[42m',
  bgYellow: '\x1b[43m',
};

const icons = {
  safe: `${c.green}✔${c.reset}`,
  caution: `${c.yellow}⚠${c.reset}`,
  unsafe: `${c.red}✖${c.reset}`,
  info: `${c.blue}ℹ${c.reset}`,
  scan: `${c.cyan}◉${c.reset}`,
  tree: `${c.gray}├──${c.reset}`,
  treeLast: `${c.gray}└──${c.reset}`,
  pipe: `${c.gray}│${c.reset}`,
  bullet: `${c.gray}•${c.reset}`,
};

// ── Credentials ─────────────────────────────────────────

const home = process.env.HOME || process.env.USERPROFILE || '';
const xdgConfig = process.env.XDG_CONFIG_HOME || path.join(home, '.config');
const USER_CRED_DIR = path.join(xdgConfig, 'agentaudit');
const USER_CRED_FILE = path.join(USER_CRED_DIR, 'credentials.json');
const SKILL_CRED_FILE = path.join(SKILL_DIR, 'config', 'credentials.json');
const PROFILE_CACHE_FILE = path.join(USER_CRED_DIR, 'profile-cache.json');
const HISTORY_DIR = path.join(USER_CRED_DIR, 'history');

function saveHistory(report) {
  try {
    fs.mkdirSync(HISTORY_DIR, { recursive: true });
    const slug = report.skill_slug || 'unknown';
    const model = (report.audit_model || 'unknown').replace(/[^a-z0-9-]/gi, '-').slice(0, 30);
    const ts = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
    const filename = `${ts}_${slug}_${model}.json`;
    fs.writeFileSync(path.join(HISTORY_DIR, filename), JSON.stringify(report, null, 2));
  } catch {}
}

function loadHistory(limit = 20) {
  try {
    if (!fs.existsSync(HISTORY_DIR)) return [];
    const files = fs.readdirSync(HISTORY_DIR)
      .filter(f => f.endsWith('.json'))
      .sort()
      .reverse()
      .slice(0, limit);
    return files.map(f => {
      try {
        const data = JSON.parse(fs.readFileSync(path.join(HISTORY_DIR, f), 'utf8'));
        data._file = f;
        return data;
      } catch { return null; }
    }).filter(Boolean);
  } catch { return []; }
}

function loadCredentials() {
  for (const f of [SKILL_CRED_FILE, USER_CRED_FILE]) {
    if (fs.existsSync(f)) {
      try {
        const data = JSON.parse(fs.readFileSync(f, 'utf8'));
        if (data.api_key) return data;
      } catch {}
    }
  }
  if (process.env.AGENTAUDIT_API_KEY) {
    return { api_key: process.env.AGENTAUDIT_API_KEY, agent_name: 'env' };
  }
  return null;
}

function loadLlmConfig() {
  for (const f of [SKILL_CRED_FILE, USER_CRED_FILE]) {
    if (fs.existsSync(f)) {
      try {
        const data = JSON.parse(fs.readFileSync(f, 'utf8'));
        if (data.llm_model || data.preferred_provider) {
          return { llm_model: data.llm_model || null, preferred_provider: data.preferred_provider || null };
        }
      } catch {}
    }
  }
  return null;
}

function saveLlmConfig(model, provider) {
  // Merge into existing credentials
  let existing = {};
  if (fs.existsSync(USER_CRED_FILE)) {
    try { existing = JSON.parse(fs.readFileSync(USER_CRED_FILE, 'utf8')); } catch {}
  }
  if (model !== undefined) existing.llm_model = model;
  if (provider !== undefined) existing.preferred_provider = provider;
  const json = JSON.stringify(existing, null, 2);
  fs.mkdirSync(USER_CRED_DIR, { recursive: true });
  fs.writeFileSync(USER_CRED_FILE, json, { mode: 0o600 });
  try {
    let skillExisting = {};
    if (fs.existsSync(SKILL_CRED_FILE)) {
      try { skillExisting = JSON.parse(fs.readFileSync(SKILL_CRED_FILE, 'utf8')); } catch {}
    }
    if (model !== undefined) skillExisting.llm_model = model;
    if (provider !== undefined) skillExisting.preferred_provider = provider;
    fs.mkdirSync(path.dirname(SKILL_CRED_FILE), { recursive: true });
    fs.writeFileSync(SKILL_CRED_FILE, JSON.stringify(skillExisting, null, 2), { mode: 0o600 });
  } catch {}
}

function resolveProvider() {
  const config = loadLlmConfig();
  const preferred = config?.preferred_provider;

  if (preferred) {
    // Find provider by name, check if any of their keys is set
    const match = LLM_PROVIDERS.find(p => p.provider === preferred && process.env[p.key]);
    if (match) return match;
    // Key missing for preferred provider — warn + fallback
    const providerInfo = LLM_PROVIDERS.find(p => p.provider === preferred);
    if (providerInfo && !quietMode) {
      console.log(`  ${c.yellow}Preferred provider "${providerInfo.name}" missing key (${providerInfo.key}), falling back...${c.reset}`);
    }
  }

  // Fallback: first match wins
  return LLM_PROVIDERS.find(p => process.env[p.key]) || null;
}

function resolveModel(modelName) {
  // Shorthand aliases for recommended models
  const aliases = {
    'opus': 'claude-opus-4-20250514',
    'sonnet': 'claude-sonnet-4-20250514',
    'gemini-3.1-pro': 'google/gemini-3.1-pro-preview',
    'gemini-3.1-flash': 'google/gemini-3.1-flash-preview',
  };
  if (aliases[modelName.toLowerCase()]) modelName = aliases[modelName.toLowerCase()];
  // model with '/' → OpenRouter
  if (modelName.includes('/')) {
    const p = LLM_PROVIDERS.find(p => p.provider === 'openrouter' && process.env[p.key]);
    if (p) return { ...p, model: modelName };
    return null;
  }
  // Known prefix → native provider
  const prefixes = [
    ['claude', 'anthropic'], ['gemini', 'google'], ['gpt', 'openai'],
    ['deepseek', 'deepseek'], ['mistral', 'mistral'], ['grok', 'xai'], ['glm', 'zhipu'],
  ];
  for (const [prefix, prov] of prefixes) {
    if (modelName.toLowerCase().startsWith(prefix)) {
      const p = LLM_PROVIDERS.find(p => p.provider === prov && process.env[p.key]);
      if (p) return { ...p, model: modelName };
    }
  }
  // Check PROVIDER_MODELS for exact match
  for (const [prov, models] of Object.entries(PROVIDER_MODELS)) {
    if (models.some(m => m.value === modelName)) {
      const p = LLM_PROVIDERS.find(p => p.provider === prov && process.env[p.key]);
      if (p) return { ...p, model: modelName };
    }
  }
  // Last resort: OpenRouter
  const or = LLM_PROVIDERS.find(p => p.provider === 'openrouter' && process.env[p.key]);
  if (or) return { ...or, model: modelName };
  return null;
}

function saveCredentials(data) {
  const json = JSON.stringify(data, null, 2);
  fs.mkdirSync(USER_CRED_DIR, { recursive: true });
  fs.writeFileSync(USER_CRED_FILE, json, { mode: 0o600 });
  try {
    fs.mkdirSync(path.dirname(SKILL_CRED_FILE), { recursive: true });
    fs.writeFileSync(SKILL_CRED_FILE, json, { mode: 0o600 });
  } catch {}
}

function loadProfileCache() {
  try {
    if (!fs.existsSync(PROFILE_CACHE_FILE)) return null;
    const data = JSON.parse(fs.readFileSync(PROFILE_CACHE_FILE, 'utf8'));
    // TTL: 10 minutes
    if (data.fetched_at && Date.now() - data.fetched_at < 10 * 60 * 1000) return data;
    return null; // expired
  } catch { return null; }
}

function saveProfileCache(data) {
  try {
    fs.mkdirSync(USER_CRED_DIR, { recursive: true });
    fs.writeFileSync(PROFILE_CACHE_FILE, JSON.stringify({
      agent_name: data.agent_name,
      rank: data.rank,
      total_points: data.total_points,
      total_reports: data.total_reports,
      fetched_at: Date.now(),
    }, null, 2), { mode: 0o600 });
  } catch {}
}

function askQuestion(question) {
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  return new Promise(resolve => rl.question(question, answer => { rl.close(); resolve(answer.trim()); }));
}

/**
 * Interactive multi-select in terminal. No dependencies.
 * items: [{ label, sublabel?, value, checked? }]
 * Returns: array of selected values
 */
function multiSelect(items, { title = 'Select items', hint = 'Space=toggle  ↑↓=move  a=all  n=none  Enter=confirm' } = {}) {
  return new Promise((resolve) => {
    if (!process.stdin.isTTY) {
      // Non-interactive: return all items
      resolve(items.map(i => i.value));
      return;
    }
    
    const selected = new Set(items.filter(i => i.checked).map((_, idx) => idx));
    let cursor = 0;
    
    const render = () => {
      // Move cursor up to overwrite previous render
      process.stdout.write(`\x1b[${items.length + 3}A\x1b[J`);
      draw();
    };
    
    const draw = () => {
      console.log(`  ${c.bold}${title}${c.reset}  ${c.dim}(${selected.size}/${items.length} selected)${c.reset}`);
      console.log(`  ${c.dim}${hint}${c.reset}`);
      console.log();
      for (let i = 0; i < items.length; i++) {
        const item = items[i];
        const isCursor = i === cursor;
        const isSelected = selected.has(i);
        const pointer = isCursor ? `${c.cyan}❯${c.reset}` : ' ';
        const checkbox = isSelected ? `${c.green}◉${c.reset}` : `${c.dim}○${c.reset}`;
        const label = isCursor ? `${c.bold}${item.label}${c.reset}` : item.label;
        const sub = item.sublabel ? `  ${c.dim}${item.sublabel}${c.reset}` : '';
        console.log(` ${pointer} ${checkbox}  ${label}${sub}`);
      }
    };
    
    // Initial draw
    draw();
    
    process.stdin.setRawMode(true);
    process.stdin.resume();
    process.stdin.setEncoding('utf8');
    
    const cleanup = () => {
      try { process.stdin.setRawMode(false); } catch {}
      process.stdin.pause();
      process.stdin.removeListener('data', onData);
    };

    const onData = (key) => {
      // Ctrl+C — restore terminal state and exit cleanly
      if (key === '\x03') {
        cleanup();
        console.log();
        process.exit(0);
      }
      
      // Enter
      if (key === '\r' || key === '\n') {
        cleanup();
        resolve(items.filter((_, i) => selected.has(i)).map(i => i.value));
        return;
      }
      
      // Space — toggle
      if (key === ' ') {
        if (selected.has(cursor)) selected.delete(cursor);
        else selected.add(cursor);
        render();
        return;
      }
      
      // a — select all
      if (key === 'a') {
        for (let i = 0; i < items.length; i++) selected.add(i);
        render();
        return;
      }
      
      // n — select none
      if (key === 'n') {
        selected.clear();
        render();
        return;
      }
      
      // Arrow up / k
      if (key === '\x1b[A' || key === 'k') {
        cursor = (cursor - 1 + items.length) % items.length;
        render();
        return;
      }
      
      // Arrow down / j
      if (key === '\x1b[B' || key === 'j') {
        cursor = (cursor + 1) % items.length;
        render();
        return;
      }
    };
    
    process.stdin.on('data', onData);
  });
}

/**
 * Interactive single-select in terminal. No dependencies.
 * items: [{ label, sublabel?, value }]
 * Returns: selected value (or null if cancelled)
 */
function singleSelect(items, { title = 'Select', hint = '↑↓=move  Enter=select  Esc=cancel' } = {}) {
  return new Promise((resolve) => {
    if (!process.stdin.isTTY) {
      resolve(items[0]?.value || null);
      return;
    }

    let cursor = 0;

    const render = () => {
      process.stdout.write(`\x1b[${items.length + 3}A\x1b[J`);
      draw();
    };

    const draw = () => {
      console.log(`  ${c.bold}${title}${c.reset}`);
      console.log(`  ${c.dim}${hint}${c.reset}`);
      console.log();
      for (let i = 0; i < items.length; i++) {
        const item = items[i];
        const isCursor = i === cursor;
        const pointer = isCursor ? `${c.cyan}❯${c.reset}` : ' ';
        const label = isCursor ? `${c.bold}${c.cyan}${item.label}${c.reset}` : item.label;
        const sub = item.sublabel ? `  ${c.dim}${item.sublabel}${c.reset}` : '';
        console.log(` ${pointer}  ${label}${sub}`);
      }
    };

    draw();

    process.stdin.setRawMode(true);
    process.stdin.resume();
    process.stdin.setEncoding('utf8');

    const onData = (key) => {
      if (key === '\x03' || key === '\x1b') {
        process.stdin.setRawMode(false);
        process.stdin.pause();
        process.stdin.removeListener('data', onData);
        console.log();
        resolve(null);
        return;
      }
      if (key === '\r' || key === '\n') {
        process.stdin.setRawMode(false);
        process.stdin.pause();
        process.stdin.removeListener('data', onData);
        resolve(items[cursor].value);
        return;
      }
      if (key === '\x1b[A' || key === 'k') {
        cursor = (cursor - 1 + items.length) % items.length;
        render();
        return;
      }
      if (key === '\x1b[B' || key === 'j') {
        cursor = (cursor + 1) % items.length;
        render();
        return;
      }
    };

    process.stdin.on('data', onData);
  });
}

async function validateApiKey(apiKey) {
  try {
    const res = await fetch(`${REGISTRY_URL}/api/auth/validate`, {
      headers: { 'Authorization': `Bearer ${apiKey}` },
      signal: AbortSignal.timeout(10_000),
    });
    if (res.ok) {
      const data = await res.json();
      return { valid: true, agent_name: data.agent_name || null };
    }
    return { valid: false, agent_name: null };
  } catch {
    return { valid: false, agent_name: null };
  }
}

async function setupCommand() {
  console.log(`  ${c.bold}AgentAudit Setup${c.reset}`);
  console.log(`  ${c.dim}Sign in to upload audit reports to agentaudit.dev${c.reset}`);
  console.log();

  const existing = loadCredentials();
  if (existing) {
    console.log(`  ${icons.safe}  Already logged in as ${c.bold}${existing.agent_name}${c.reset}`);
    console.log(`  ${c.dim}Key: ${existing.api_key.slice(0, 12)}...${c.reset}`);
    console.log();
    const answer = await askQuestion(`  Reconfigure? ${c.dim}(y/N)${c.reset} `);
    if (answer.toLowerCase() !== 'y') {
      console.log(`  ${c.dim}Keeping existing config.${c.reset}`);
      return;
    }
    console.log();
  }

  // Offer choice: GitHub OAuth (recommended) or manual API key
  console.log(`  ${c.bold}How do you want to sign in?${c.reset}`);
  console.log();
  console.log(`  ${c.cyan}1${c.reset}  Sign in with GitHub ${c.dim}(recommended — opens browser)${c.reset}`);
  console.log(`  ${c.cyan}2${c.reset}  Paste an API key manually ${c.dim}(from ${REGISTRY_URL}/profile)${c.reset}`);
  console.log();
  const choice = await askQuestion(`  Choice ${c.dim}(1/2, default: 1):${c.reset} `);
  console.log();

  if (choice.trim() === '2') {
    // ── Manual API key flow ──
    await setupManualKey();
  } else {
    // ── GitHub OAuth Device Flow (default) ──
    await loginCommand();
  }
}

async function setupManualKey() {
  console.log(`  ${c.bold}Step 1:${c.reset} Create an API key at ${c.cyan}${REGISTRY_URL}/profile${c.reset}`);
  console.log(`  ${c.dim}Sign in with GitHub, then click "Create API Key".${c.reset}`);
  console.log();
  const key = await askQuestion(`  ${c.bold}Step 2:${c.reset} Paste your API key here: `);
  if (!key || !key.trim()) {
    console.log(`  ${c.red}No key entered.${c.reset}`);
    return;
  }

  process.stdout.write(`  Validating...`);
  const validation = await validateApiKey(key.trim());
  if (validation.valid) {
    const agentName = validation.agent_name || 'agent';
    saveCredentials({ api_key: key.trim(), agent_name: agentName });
    console.log(` ${c.green}valid!${c.reset}`);
    console.log();
    console.log(`  ${icons.safe}  Logged in as ${c.bold}${agentName}${c.reset}`);
    console.log(`  ${c.dim}Key saved to: ${USER_CRED_FILE}${c.reset}`);
  } else {
    console.log(` ${c.red}invalid${c.reset}`);
    console.log(`  ${c.red}Key not recognized. Make sure you copied the full key from ${REGISTRY_URL}/profile${c.reset}`);
    return;
  }

  setupReadyMessage();
}

function setupReadyMessage() {
  console.log();

  // ── LLM configuration hint ──
  const llmConfig = loadLlmConfig();
  console.log(`  ${c.bold}LLM Configuration${c.reset}`);
  if (llmConfig?.llm_model || llmConfig?.preferred_provider) {
    const parts = [];
    if (llmConfig.preferred_provider) parts.push(llmConfig.preferred_provider);
    if (llmConfig.llm_model) parts.push(llmConfig.llm_model);
    console.log(`  ${icons.safe}  Current: ${c.bold}${parts.join(' → ')}${c.reset}`);
  }
  console.log(`  ${c.dim}Run ${c.cyan}agentaudit model${c.dim} to configure your LLM provider and model.${c.reset}`);
  console.log(`  ${c.dim}Deep audits require an LLM API key in your environment.${c.reset}`);
  console.log();

  console.log(`  ${c.bold}Ready!${c.reset} You can now:`);
  console.log(`  ${c.dim}•${c.reset} Discover servers: ${c.cyan}agentaudit discover${c.reset}`);
  console.log(`  ${c.dim}•${c.reset} Audit packages:   ${c.cyan}agentaudit audit <repo-url>${c.reset}  ${c.dim}(deep LLM analysis)${c.reset}`);
  console.log(`  ${c.dim}•${c.reset} Quick scan:        ${c.cyan}agentaudit scan <repo-url>${c.reset}  ${c.dim}(regex-based)${c.reset}`);
  console.log(`  ${c.dim}•${c.reset} Check registry:    ${c.cyan}agentaudit check <name>${c.reset}`);
  console.log(`  ${c.dim}•${c.reset} Submit reports via MCP in Claude/Cursor/Windsurf`);
  console.log();
}

// ── Login via GitHub Device Flow ─────────────────────────

async function loginCommand() {
  console.log(`  ${c.bold}AgentAudit Login${c.reset}`);
  console.log(`  ${c.dim}Sign in with GitHub to upload audit reports${c.reset}`);
  console.log();

  const existing = loadCredentials();
  if (existing) {
    console.log(`  ${icons.safe}  Already logged in as ${c.bold}${existing.agent_name}${c.reset}`);
    console.log(`  ${c.dim}Key: ${existing.api_key.slice(0, 12)}...${c.reset}`);
    console.log();
    const answer = await askQuestion(`  Re-authenticate? ${c.dim}(y/N)${c.reset} `);
    if (answer.toLowerCase() !== 'y') {
      console.log(`  ${c.dim}Keeping existing login.${c.reset}`);
      return;
    }
    console.log();
  }

  // Step 1: Start device flow
  process.stdout.write(`  Starting login flow...`);
  let deviceData;
  try {
    const res = await fetch(`${REGISTRY_URL}/api/auth/device`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      signal: AbortSignal.timeout(10_000),
    });
    deviceData = await res.json();
    if (!res.ok || !deviceData.device_code) {
      console.log(` ${c.red}failed${c.reset}`);
      console.log(`  ${c.red}${deviceData.error || 'Could not start login flow'}${c.reset}`);
      console.log(`  ${c.dim}Fallback: run ${c.cyan}agentaudit setup${c.dim} to paste an API key manually${c.reset}`);
      return;
    }
    console.log(` ${c.green}ok${c.reset}`);
  } catch (err) {
    console.log(` ${c.red}failed${c.reset}`);
    console.log(`  ${c.red}Could not reach ${REGISTRY_URL}${c.reset}`);
    console.log(`  ${c.dim}Fallback: run ${c.cyan}agentaudit setup${c.dim} to paste an API key manually${c.reset}`);
    return;
  }

  // Step 2: Open browser
  const verifyUrl = deviceData.verification_url;
  console.log();
  console.log(`  ${c.bold}Open this URL in your browser:${c.reset}`);
  console.log(`  ${c.cyan}${verifyUrl}${c.reset}`);
  console.log();

  // Try to auto-open browser
  try {
    const { exec } = await import('child_process');
    if (process.platform === 'darwin') {
      exec(`open "${verifyUrl}"`);
    } else if (process.platform === 'win32') {
      exec(`start "" "${verifyUrl}"`);
    } else {
      exec(`xdg-open "${verifyUrl}"`);
    }
    console.log(`  ${c.dim}(Browser should open automatically)${c.reset}`);
  } catch {}

  // Step 3: Poll for authorization
  console.log(`  ${c.dim}Waiting for GitHub authorization...${c.reset}`);
  console.log();

  const interval = (deviceData.interval || 5) * 1000;
  const maxAttempts = Math.ceil((deviceData.expires_in || 900) / (interval / 1000));

  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    await new Promise(r => setTimeout(r, interval));

    try {
      const res = await fetch(`${REGISTRY_URL}/api/auth/device?device_code=${deviceData.device_code}`, {
        signal: AbortSignal.timeout(10_000),
      });
      const data = await res.json();

      if (res.ok && data.api_key) {
        // Success!
        saveCredentials({ api_key: data.api_key, agent_name: data.agent_name });
        console.log(`\r  ${c.green}${icons.safe}  Logged in as ${c.bold}${data.agent_name}${c.reset}                `);
        console.log(`  ${c.dim}Key saved to: ${USER_CRED_FILE}${c.reset}`);
        setupReadyMessage();
        return;
      }

      if (data.error === 'authorization_pending') {
        process.stdout.write(`\r  ${c.dim}Waiting... (${attempt + 1}/${maxAttempts})${c.reset}  `);
        continue;
      }

      if (data.error === 'expired_token') {
        console.log(`\n  ${c.red}Login expired. Run ${c.cyan}agentaudit login${c.red} again.${c.reset}`);
        return;
      }

      // Unknown error
      console.log(`\n  ${c.red}${data.error || 'Unknown error'}${c.reset}`);
      return;
    } catch {
      // Network error during poll — continue trying
      continue;
    }
  }

  console.log(`\n  ${c.red}Login timed out. Run ${c.cyan}agentaudit login${c.red} again.${c.reset}`);
}

// ── Helpers ──────────────────────────────────────────────

function validateGitUrl(url) {
  // Reject URLs with shell metacharacters to prevent command injection
  if (/[;&|`$(){}!\n\r]/.test(url)) {
    throw new Error(`Rejected URL with suspicious characters: ${url.slice(0, 80)}`);
  }
  // Must look like a URL (http/https/git/ssh) or a GitHub shorthand
  if (!/^(https?:\/\/|git@|git:\/\/|ssh:\/\/)/.test(url) && !/^[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+$/.test(url)) {
    throw new Error(`Invalid repository URL: ${url.slice(0, 80)}`);
  }
}

function safeGitClone(url, destPath, timeoutMs = 30_000) {
  validateGitUrl(url);
  execFileSync('git', ['clone', '--depth', '1', url, destPath], {
    timeout: timeoutMs,
    stdio: 'pipe',
  });
}

function getVersion() {
  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, 'package.json'), 'utf8'));
    return pkg.version || '0.0.0';
  } catch { return '0.0.0'; }
}

function banner() {
  if (quietMode || jsonMode) return;
  console.log();
  const cache = loadProfileCache();
  if (cache) {
    const rankStr = cache.rank != null ? `#${cache.rank}` : '';
    const ptsStr = `${fmtNum(cache.total_points)}pts`;
    const auditsStr = `${fmtNum(cache.total_reports)} audits`;
    const profile = [cache.agent_name, rankStr, ptsStr, auditsStr].filter(Boolean).join(' \u00b7 ');
    console.log(`  ${c.bold}${c.cyan}\u25c6 AgentAudit${c.reset} ${c.dim}v${getVersion()}${c.reset}  ${c.dim}\u2502${c.reset}  ${profile}`);
  } else {
    console.log(`  ${c.bold}${c.cyan}AgentAudit${c.reset} ${c.dim}v${getVersion()}${c.reset}`);
    console.log(`  ${c.dim}Security scanner for AI packages${c.reset}`);
  }
  console.log();
}

function slugFromUrl(url) {
  const match = url.match(/github\.com\/([^/]+)\/([^/.\s]+)/);
  if (match) return match[2].toLowerCase().replace(/[^a-z0-9-]/g, '-');
  return url.replace(/[^a-z0-9]/gi, '-').toLowerCase().slice(0, 60);
}

function elapsed(startMs) {
  const ms = Date.now() - startMs;
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}

function riskBadge(score) {
  const badge = score === 0 ? `${c.bgGreen}${c.bold}${c.white} SAFE ${c.reset}`
    : score <= 10 ? `${c.bgGreen}${c.white} LOW ${c.reset}`
    : score <= 30 ? `${c.bgYellow}${c.bold} CAUTION ${c.reset}`
    : `${c.bgRed}${c.bold}${c.white} UNSAFE ${c.reset}`;
  const filled = Math.min(Math.round(score / 20), 5);
  const gaugeColor = score <= 10 ? c.green : score <= 30 ? c.yellow : c.red;
  const gauge = `${gaugeColor}${'▰'.repeat(filled)}${c.dim}${'▱'.repeat(5 - filled)}${c.reset}`;
  return `${badge} ${gauge}  ${score}/100`;
}

function severityColor(sev) {
  switch (sev) {
    case 'critical': return c.red;
    case 'high': return c.red;
    case 'medium': return c.yellow;
    case 'low': return c.blue;
    default: return c.gray;
  }
}

function severityIcon(sev) {
  switch (sev) {
    case 'critical': return `${c.red}●${c.reset}`;
    case 'high': return `${c.red}●${c.reset}`;
    case 'medium': return `${c.yellow}●${c.reset}`;
    case 'low': return `${c.blue}●${c.reset}`;
    default: return `${c.green}●${c.reset}`;
  }
}

// ── TUI Rendering Helpers ───────────────────────────────

const term = {
  clearScreen: '\x1b[2J\x1b[H',
  hideCursor: '\x1b[?25l',
  showCursor: '\x1b[?25h',
  altScreenOn: '\x1b[?1049h',
  altScreenOff: '\x1b[?1049l',
  moveTo: (r, col) => `\x1b[${r};${col}H`,
  clearLine: '\x1b[2K',
  underline: '\x1b[4m',
  noUnderline: '\x1b[24m',
};

const BOX = { tl: '╭', tr: '╮', bl: '╰', br: '╯', h: '─', v: '│', lt: '├', rt: '┤', tt: '┬', bt: '┴', x: '┼' };

// Strip ANSI escape codes for length calculations
function stripAnsi(str) {
  return str.replace(/\x1b\[[0-9;]*[a-zA-Z]/g, '');
}

function visLen(str) {
  return stripAnsi(str).length;
}

function padRight(str, len) {
  const diff = len - visLen(str);
  return diff > 0 ? str + ' '.repeat(diff) : str;
}

function padLeft(str, len) {
  const diff = len - visLen(str);
  return diff > 0 ? ' '.repeat(diff) + str : str;
}

// Truncate a string with ANSI codes to maxLen visible characters
function truncateAnsi(str, maxLen) {
  if (maxLen <= 0) return '';
  let vis = 0;
  let result = '';
  let i = 0;
  while (i < str.length) {
    if (str[i] === '\x1b') {
      const m = str.slice(i).match(/^\x1b\[[0-9;]*[a-zA-Z]/);
      if (m) { result += m[0]; i += m[0].length; continue; }
    }
    if (vis >= maxLen) break;
    result += str[i];
    vis++;
    i++;
  }
  return result + c.reset;
}

function drawBox(title, contentLines, width) {
  const inner = width - 4; // 2 for "│ " + 2 for " │"
  const totalDash = inner + 2; // total horizontal line chars between corners
  const lines = [];
  let titleStr = title ? ` ${title} ` : '';
  let titleLen = visLen(titleStr);
  // Clamp title if wider than available border space
  if (titleLen >= totalDash - 1) {
    const maxTitle = Math.max(1, totalDash - 4);
    titleStr = ` ${title.slice(0, maxTitle)}… `;
    titleLen = visLen(titleStr);
  }
  // Top: ╭─ Title ────────────╮  (1 dash before title + title + remaining dashes)
  const topDash = BOX.h.repeat(Math.max(0, totalDash - 1 - titleLen));
  lines.push(`  ${BOX.tl}${c.dim}${BOX.h}${c.reset}${c.bold}${titleStr}${c.reset}${c.dim}${topDash}${c.reset}${BOX.tr}`);
  for (const line of contentLines) {
    // Truncate content that exceeds box inner width
    const vl = visLen(line);
    const display = vl > inner ? truncateAnsi(line, inner - 1) + '…' : line;
    lines.push(`  ${BOX.v} ${padRight(display, inner + 1)}${BOX.v}`);
  }
  lines.push(`  ${BOX.bl}${c.dim}${BOX.h.repeat(totalDash)}${c.reset}${BOX.br}`);
  return lines;
}

// ████████░░░░ proportional bar
function renderBar(value, maxValue, maxWidth) {
  if (maxValue <= 0 || value <= 0) return c.dim + '░'.repeat(maxWidth) + c.reset;
  const filled = Math.min(Math.round((value / maxValue) * maxWidth), maxWidth);
  const empty = maxWidth - filled;
  return c.cyan + '█'.repeat(filled) + c.dim + '░'.repeat(empty) + c.reset;
}

// [████████░░] 89%
function renderGauge(value, max, width) {
  const pct = max > 0 ? Math.round((value / max) * 100) : 0;
  const inner = width - 2; // subtract brackets
  const filled = Math.min(Math.round((pct / 100) * inner), inner);
  const empty = inner - filled;
  const color = pct >= 80 ? c.green : pct >= 50 ? c.yellow : c.red;
  return `[${color}${'█'.repeat(filled)}${c.dim}${'░'.repeat(empty)}${c.reset}] ${pct}%`;
}

// ●●●○○ colored severity dots
function severityDots(breakdown) {
  const parts = [];
  const critical = breakdown?.critical || 0;
  const high = breakdown?.high || 0;
  const medium = breakdown?.medium || 0;
  const low = breakdown?.low || 0;
  for (let i = 0; i < Math.min(critical, 3); i++) parts.push(`${c.red}●${c.reset}`);
  for (let i = 0; i < Math.min(high, 3); i++) parts.push(`${c.red}●${c.reset}`);
  for (let i = 0; i < Math.min(medium, 2); i++) parts.push(`${c.yellow}●${c.reset}`);
  for (let i = 0; i < Math.min(low, 2); i++) parts.push(`${c.blue}●${c.reset}`);
  // fill remaining with empty dots up to 5
  while (parts.length < 5) parts.push(`${c.dim}○${c.reset}`);
  return parts.slice(0, 5).join('');
}

// ▁▂▃▅▇█▆▃ mini sparkline
function sparkline(values) {
  const chars = '▁▂▃▄▅▆▇█';
  if (!values || values.length === 0) return '';
  const max = Math.max(...values, 1);
  return values.map(v => {
    const idx = Math.min(Math.round((v / max) * (chars.length - 1)), chars.length - 1);
    return chars[idx];
  }).join('');
}

// ─── Section Header ─────────── labeled divider
function sectionHeader(title, width = 60) {
  const dashAfter = Math.max(3, width - 5 - title.length);
  return `  ${c.dim}───${c.reset} ${c.bold}${title}${c.reset} ${c.dim}${'─'.repeat(dashAfter)}${c.reset}`;
}

// █████░░░░░░░░░░░░░░ coverage bar
function coverageBar(filled, total, width = 20) {
  if (total === 0) return `${c.dim}${'░'.repeat(width)}${c.reset}  0/0`;
  const barFilled = Math.max(filled > 0 ? 1 : 0, Math.round((filled / total) * width));
  const barEmpty = width - barFilled;
  const pct = Math.round((filled / total) * 100);
  const color = pct >= 80 ? c.green : pct >= 50 ? c.yellow : c.red;
  return `${color}${'█'.repeat(barFilled)}${c.dim}${'░'.repeat(barEmpty)}${c.reset}  ${filled}/${total} (${pct}%)`;
}

// Severity histogram for findings
function severityHistogram(findings) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) {
    const sev = (f.severity || '').toLowerCase();
    if (counts[sev] !== undefined) counts[sev]++;
  }
  const max = Math.max(...Object.values(counts), 1);
  const lines = [];
  for (const sev of ['critical', 'high', 'medium', 'low']) {
    const count = counts[sev];
    if (count === 0) continue;
    const barLen = Math.max(1, Math.round((count / max) * 24));
    const sc = severityColor(sev);
    const label = sev.toUpperCase().padEnd(10);
    lines.push(`  ${sc}${label}${c.reset} ${sc}${'█'.repeat(barLen)}${c.reset}${' '.repeat(24 - barLen)}  ${count}`);
  }
  return lines;
}

// ▰▰▰▱ step progress indicator
function stepProgress(current, total) {
  return `${c.cyan}${'▰'.repeat(current)}${c.dim}${'▱'.repeat(total - current)}${c.reset}`;
}

function fmtNum(n) {
  if (n == null) return '0';
  return n.toLocaleString('en-US');
}

function fmtPct(n) {
  if (n == null) return '0%';
  return Math.round(n) + '%';
}

function dashboardBanner() {
  const ver = getVersion();
  const inner = 35;
  const line1 = `  \u25C6  AgentAudit  v${ver}`;
  const line2 = `  Security Registry for AI Agents`;
  const pad1 = Math.max(0, inner - line1.length);
  const pad2 = Math.max(0, inner - line2.length);
  return [
    `  ${BOX.tl}${c.dim}${BOX.h.repeat(inner)}${c.reset}${BOX.tr}`,
    `  ${BOX.v}${c.bold}${c.cyan}${line1}${c.reset}${' '.repeat(pad1)}${BOX.v}`,
    `  ${BOX.v}${c.dim}${line2}${c.reset}${' '.repeat(pad2)}${BOX.v}`,
    `  ${BOX.bl}${c.dim}${BOX.h.repeat(inner)}${c.reset}${BOX.br}`,
  ];
}

// ── File Collection (same logic as MCP server) ──────────

function formatApiError(error, provider, statusCode) {
  // Extract error message from various API response formats
  const msg = (typeof error === 'string' ? error : error?.message || error?.error?.message || JSON.stringify(error)).toLowerCase();

  // Authentication errors
  if (statusCode === 401 || statusCode === 403 || msg.includes('invalid api key') || msg.includes('invalid x-api-key') ||
      msg.includes('incorrect api key') || msg.includes('authentication') || msg.includes('unauthorized') ||
      msg.includes('invalid_api_key') || msg.includes('permission denied')) {
    return { text: 'Invalid or expired API key', hint: `Check your ${provider} API key. Run: echo $${provider}_API_KEY` };
  }

  // Rate limits / quota
  if (statusCode === 429 || msg.includes('rate limit') || msg.includes('rate_limit') || msg.includes('too many requests') ||
      msg.includes('quota') || msg.includes('insufficient_quota') || msg.includes('billing') ||
      msg.includes('exceeded') || msg.includes('no credits') || msg.includes('credit') ||
      msg.includes('overloaded') || msg.includes('capacity')) {
    return { text: 'Rate limit or quota exceeded', hint: 'Wait a moment and retry, or check your billing/credits at your provider dashboard' };
  }

  // Model not found
  if (statusCode === 404 || msg.includes('not found') || msg.includes('not a valid model') ||
      msg.includes('model_not_found') || msg.includes('does not exist') || msg.includes('invalid model')) {
    return { text: 'Model not found', hint: `"${msg}" — check model name with: agentaudit model` };
  }

  // Context length / payload too large
  if (statusCode === 413 || msg.includes('context length') || msg.includes('too long') ||
      msg.includes('maximum') || msg.includes('token limit') || msg.includes('content_too_large')) {
    return { text: 'Input too large for model', hint: 'The repository has too many files. Try a smaller repo or a model with larger context window' };
  }

  // Server errors
  if (statusCode >= 500) {
    return { text: `Provider server error (HTTP ${statusCode})`, hint: `${provider} might be experiencing issues. Try again later` };
  }

  // Fallback
  return null;
}

/**
 * Validate that a parsed object looks like a valid audit report.
 * Must have at least: findings (array) and one of skill_slug/risk_score/result.
 */
function isValidReportSchema(obj) {
  if (!obj || typeof obj !== 'object') return false;
  if (!Array.isArray(obj.findings)) return false;
  // Must have at least one identifying field
  if (!('skill_slug' in obj) && !('risk_score' in obj) && !('result' in obj)) return false;
  return true;
}

function extractJSON(text) {
  // 1. Try parsing the entire text as JSON directly
  try {
    const parsed = JSON.parse(text.trim());
    if (isValidReportSchema(parsed)) return parsed;
  } catch {}

  // 2. Strip markdown code fences — try last fence first (report is usually at the end)
  const fenceMatches = [...text.matchAll(/```(?:json)?\s*\n?([\s\S]*?)\n?\s*```/g)];
  for (let i = fenceMatches.length - 1; i >= 0; i--) {
    try {
      const parsed = JSON.parse(fenceMatches[i][1].trim());
      if (isValidReportSchema(parsed)) return parsed;
    } catch {}
  }

  // 3. Find ALL balanced top-level { ... } blocks, try each (prefer largest valid one)
  const blocks = [];
  let searchFrom = 0;
  while (searchFrom < text.length) {
    const start = text.indexOf('{', searchFrom);
    if (start === -1) break;
    let depth = 0, inStr = false, esc = false;
    let end = -1;
    for (let i = start; i < text.length; i++) {
      const ch = text[i];
      if (esc) { esc = false; continue; }
      if (ch === '\\' && inStr) { esc = true; continue; }
      if (ch === '"') { inStr = !inStr; continue; }
      if (inStr) continue;
      if (ch === '{') depth++;
      else if (ch === '}') { depth--; if (depth === 0) { end = i; break; } }
    }
    if (end > start) {
      blocks.push(text.slice(start, end + 1));
      searchFrom = end + 1;
    } else {
      searchFrom = start + 1;
    }
  }
  // Try largest block first (the report JSON is usually the biggest)
  blocks.sort((a, b) => b.length - a.length);
  for (const block of blocks) {
    try {
      const parsed = JSON.parse(block);
      if (isValidReportSchema(parsed)) return parsed;
    } catch {}
  }

  return null;
}

const MAX_FILE_SIZE = 50_000;
const MAX_TOTAL_SIZE = 300_000;
const SKIP_DIRS = new Set([
  'node_modules', '.git', '__pycache__', '.venv', 'venv', 'dist', 'build',
  '.next', '.nuxt', 'coverage', '.pytest_cache', '.mypy_cache', 'vendor',
  'test', 'tests', '__tests__', 'spec', 'specs', 'docs', 'doc',
  'examples', 'example', 'fixtures', '.vscode', '.idea',
  'e2e', 'benchmark', 'benchmarks', '.tox', '.eggs', 'htmlcov',
]);
const SKIP_EXTENSIONS = new Set([
  '.lock', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.woff',
  '.woff2', '.ttf', '.eot', '.mp3', '.mp4', '.zip', '.tar', '.gz',
  '.map', '.min.js', '.min.css', '.d.ts', '.pyc', '.pyo', '.so',
  '.dylib', '.dll', '.exe', '.bin', '.dat', '.db', '.sqlite',
]);

function collectFiles(dir, basePath = '', collected = [], totalSize = { bytes: 0 }, _visitedPaths = new Set()) {
  if (totalSize.bytes >= MAX_TOTAL_SIZE) return collected;

  // Symlink loop protection: resolve real path and track visited directories
  let realDir;
  try { realDir = fs.realpathSync(dir); } catch { return collected; }
  if (_visitedPaths.has(realDir)) return collected;
  _visitedPaths.add(realDir);

  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
  catch { return collected; }
  entries.sort((a, b) => a.name.localeCompare(b.name));
  for (const entry of entries) {
    if (totalSize.bytes >= MAX_TOTAL_SIZE) break;
    const relPath = basePath ? `${basePath}/${entry.name}` : entry.name;
    const fullPath = path.join(dir, entry.name);

    // Skip symlinks that point to directories (prevent symlink traversal attacks)
    if (entry.isSymbolicLink()) {
      try {
        const target = fs.realpathSync(fullPath);
        if (fs.statSync(target).isDirectory()) continue; // skip symlinked dirs entirely
      } catch { continue; }
    }

    if (entry.isDirectory()) {
      // Special: scan .github/workflows/ (security-critical CI/CD files)
      if (entry.name === '.github') {
        const wfDir = path.join(fullPath, 'workflows');
        try { if (fs.statSync(wfDir).isDirectory()) collectFiles(wfDir, relPath + '/workflows', collected, totalSize, _visitedPaths); } catch {}
        continue;
      }
      if (SKIP_DIRS.has(entry.name) || entry.name.startsWith('.')) continue;
      collectFiles(fullPath, relPath, collected, totalSize, _visitedPaths);
    } else {
      const ext = path.extname(entry.name).toLowerCase();
      if (SKIP_EXTENSIONS.has(ext)) continue;
      try {
        const stat = fs.statSync(fullPath);
        if (stat.size > MAX_FILE_SIZE || stat.size === 0) continue;
        const content = fs.readFileSync(fullPath, 'utf8');
        totalSize.bytes += content.length;
        collected.push({ path: relPath, content, size: stat.size });
      } catch {}
    }
  }
  return collected;
}

// ── Detect package properties ───────────────────────────

function detectPackageInfo(repoPath, files) {
  const info = { type: 'unknown', tools: [], prompts: [], language: 'unknown', entrypoint: null };
  
  // Detect language
  const exts = files.map(f => path.extname(f.path).toLowerCase());
  const extCounts = {};
  exts.forEach(e => { extCounts[e] = (extCounts[e] || 0) + 1; });
  const topExt = Object.entries(extCounts).sort((a, b) => b[1] - a[1])[0]?.[0];
  
  const langMap = { '.py': 'Python', '.js': 'JavaScript', '.ts': 'TypeScript', '.mjs': 'JavaScript', '.rs': 'Rust', '.go': 'Go', '.java': 'Java', '.rb': 'Ruby' };
  info.language = langMap[topExt] || topExt || 'unknown';
  
  // Detect package type
  const allContent = files.map(f => f.content).join('\n');
  if (allContent.includes('modelcontextprotocol') || allContent.includes('FastMCP') || allContent.includes('mcp.server') || allContent.includes('mcp_server') || allContent.includes('mcp-go')) {
    info.type = 'mcp-server';
  } else if (files.some(f => f.path.toLowerCase() === 'skill.md')) {
    info.type = 'agent-skill';
  } else if (allContent.includes('#!/usr/bin/env') || allContent.includes('argparse') || allContent.includes('commander')) {
    info.type = 'cli-tool';
  } else {
    info.type = 'library';
  }
  
  // Extract MCP tools — only from files that reference MCP SDK
  const mcpKeywords = ['modelcontextprotocol', 'FastMCP', 'mcp.server', 'mcp_server', '@mcp.tool', '@server.tool', '.tool(', 'ListTools', 'CallTool'];
  const mcpFiles = files.filter(f => mcpKeywords.some(kw => f.content.includes(kw)));
  // Fallback: if no MCP-specific files found, try entrypoint files
  if (mcpFiles.length === 0) {
    const entryNames = ['index.js', 'index.ts', 'index.mjs', 'main.py', 'server.py', 'app.py', 'src/index.ts', 'src/main.ts', 'src/index.js'];
    for (const f of files) {
      if (entryNames.includes(f.path)) mcpFiles.push(f);
    }
  }

  const toolPatterns = [
    // JS/TS MCP SDK: server.tool('name', ...) or .setTool('name', ...)
    /\.tool\s*\(\s*['"]([a-z_][a-z0-9_]*)['"]/gi,
    // Python: @mcp.tool() / @server.tool() followed by def name
    /@(?:mcp|server)\.tool\s*\(.*?\)[\s\S]*?def\s+([a-z_][a-z0-9_]*)/gi,
    // Python: Tool(name="xxx")
    /Tool\s*\(\s*name\s*=\s*['"]([a-z_][a-z0-9_]*)['"]/gi,
    // ListTools handler: { name: "tool_name", description: ... }
    /{\s*(?:['"]?)name(?:['"]?)\s*:\s*['"]([a-z_][a-z0-9_]*)['"]\s*,\s*(?:['"]?)description(?:['"]?)\s*:/gi,
  ];

  const toolBlacklist = new Set(['type', 'name', 'string', 'object', 'number', 'boolean', 'array', 'required', 'description', 'default', 'null', 'true', 'false', 'none', 'test', 'self', 'args', 'kwargs', 'input', 'output', 'result', 'data', 'error', 'value', 'index', 'item', 'list', 'dict', 'set', 'map', 'key', 'url', 'env', 'config', 'options']);

  const toolSet = new Set();
  for (const file of mcpFiles) {
    for (const pattern of toolPatterns) {
      pattern.lastIndex = 0;
      let m;
      while ((m = pattern.exec(file.content)) !== null) {
        const name = m[1] || m[2];
        if (name && name.length > 2 && name.length < 50 && !toolBlacklist.has(name)) {
          toolSet.add(name);
        }
      }
    }
  }
  info.tools = [...toolSet];
  
  // Extract prompts (look for prompt definitions)
  const promptPatterns = [
    /(?:prompt|PROMPT)['":\s]+['"]([a-z_][a-z0-9_]*)['"]/gi,
    /@(?:mcp|server)\.prompt\(\)[\s\S]*?def\s+([a-z_][a-z0-9_]*)/gi,
  ];
  const promptSet = new Set();
  for (const file of files) {
    for (const pattern of promptPatterns) {
      pattern.lastIndex = 0;
      let m;
      while ((m = pattern.exec(file.content)) !== null) {
        if (m[1] && m[1].length > 2) promptSet.add(m[1]);
      }
    }
  }
  info.prompts = [...promptSet];
  
  // Detect entrypoint
  const entryFiles = ['index.js', 'index.ts', 'index.mjs', 'main.py', 'server.py', 'app.py', 'src/index.ts', 'src/main.ts', 'src/index.js'];
  for (const ef of entryFiles) {
    if (files.some(f => f.path === ef)) { info.entrypoint = ef; break; }
  }

  // Extract package version from manifest files
  info.version = null;
  const versionSources = [
    { file: 'package.json', extract: c => { try { return JSON.parse(c).version; } catch { return null; } } },
    { file: 'pyproject.toml', extract: c => { const m = c.match(/^\s*version\s*=\s*["']([^"']+)["']/m); return m?.[1] || null; } },
    { file: 'setup.py', extract: c => { const m = c.match(/version\s*=\s*["']([^"']+)["']/); return m?.[1] || null; } },
    { file: 'setup.cfg', extract: c => { const m = c.match(/^\s*version\s*=\s*(.+)$/m); return m?.[1]?.trim() || null; } },
    { file: 'Cargo.toml', extract: c => { const m = c.match(/^\s*version\s*=\s*["']([^"']+)["']/m); return m?.[1] || null; } },
  ];
  for (const vs of versionSources) {
    const f = files.find(f => f.path === vs.file || f.path.endsWith('/' + vs.file));
    if (f) {
      const v = vs.extract(f.content);
      if (v) { info.version = v; break; }
    }
  }

  return info;
}

// ── Quick static checks ─────────────────────────────────

function quickChecks(files) {
  const findings = [];
  
  const checks = [
    {
      id: 'EXEC_INJECTION',
      title: 'Command injection risk',
      severity: 'high',
      pattern: /(?:exec(?:Sync)?|spawn|child_process|subprocess|os\.system|os\.popen|Popen)\s*\([^)]*(?:\$\{|`|\+\s*(?:req|input|args|param|user|query))/i,
      category: 'injection',
    },
    {
      id: 'EVAL_USAGE',
      title: 'Dynamic code evaluation',
      severity: 'high',
      pattern: /(?:^|[^a-z])eval\s*\([^)]*(?:input|req|user|param|arg|query)/im,
      category: 'injection',
    },
    {
      id: 'HARDCODED_SECRET',
      title: 'Potential hardcoded secret',
      severity: 'medium',
      pattern: /(?:api[_-]?key|password|secret|token)\s*[:=]\s*['"][A-Za-z0-9+/=_-]{16,}['"]/i,
      category: 'secrets',
    },
    {
      id: 'SSL_DISABLED',
      title: 'SSL/TLS verification disabled',
      severity: 'medium',
      pattern: /(?:rejectUnauthorized\s*:\s*false|verify\s*=\s*False|VERIFY_SSL\s*=\s*false|NODE_TLS_REJECT_UNAUTHORIZED|InsecureRequestWarning)/i,
      category: 'crypto',
    },
    {
      id: 'PATH_TRAVERSAL',
      title: 'Potential path traversal',
      severity: 'medium',
      pattern: /(?:\.\.\/|\.\.\\|path\.join|os\.path\.join)\s*\([^)]*(?:input|req|user|param|arg|query)/i,
      category: 'filesystem',
    },
    {
      id: 'CORS_WILDCARD',
      title: 'Wildcard CORS origin',
      severity: 'low',
      pattern: /(?:Access-Control-Allow-Origin|cors)\s*[:({]\s*['"]\*/i,
      category: 'network',
    },
    {
      id: 'TELEMETRY',
      title: 'Undisclosed telemetry',
      severity: 'low',
      pattern: /(?:posthog|mixpanel|analytics|telemetry|tracking|sentry).*(?:init|setup|track|capture)/i,
      category: 'privacy',
    },
    {
      id: 'SHELL_EXEC',
      title: 'Shell command execution',
      severity: 'high',
      pattern: /(?:subprocess\.(?:run|call|Popen)|os\.system|os\.popen|execSync|child_process\.exec)\s*\(/i,
      category: 'injection',
    },
    {
      id: 'SQL_INJECTION',
      title: 'Potential SQL injection',
      severity: 'high',
      pattern: /(?:execute|query|raw)\s*\(\s*(?:f['"]|['"].*?%s|['"].*?\{|['"].*?\+)/i,
      category: 'injection',
    },
    {
      id: 'YAML_UNSAFE',
      title: 'Unsafe YAML loading',
      severity: 'medium',
      pattern: /yaml\.(?:load|unsafe_load)\s*\(/i,
      category: 'deserialization',
    },
    {
      id: 'PICKLE_LOAD',
      title: 'Unsafe deserialization (pickle)',
      severity: 'high',
      pattern: /pickle\.loads?\s*\(/i,
      category: 'deserialization',
    },
    {
      id: 'PROMPT_INJECTION',
      title: 'Prompt injection vector',
      severity: 'high',
      pattern: /(?:<IMPORTANT>|<SYSTEM>|ignore previous|you are now|new instructions)/i,
      category: 'prompt-injection',
    },
  ];
  
  for (const file of files) {
    for (const check of checks) {
      const match = check.pattern.exec(file.content);
      if (match) {
        // Find line number
        const lines = file.content.slice(0, match.index).split('\n');
        findings.push({
          ...check,
          file: file.path,
          line: lines.length,
          snippet: match[0].trim().slice(0, 80),
          confidence: 'medium',
        });
      }
    }
  }
  
  return findings;
}

// ── Registry check ──────────────────────────────────────

async function checkRegistry(slug) {
  try {
    const res = await fetch(`${REGISTRY_URL}/api/packages/${encodeURIComponent(slug)}`, {
      signal: AbortSignal.timeout(5000),
    });
    if (res.ok) return await res.json();
  } catch {}
  return null;
}

// ── Print results ───────────────────────────────────────

function printScanResult(url, info, files, findings, registryData, duration) {
  if (jsonMode) return; // JSON mode handles output separately
  
  const slug = slugFromUrl(url);
  
  // Quiet mode: compact one-line-per-package output
  if (quietMode) {
    if (findings.length > 0) {
      const bySev = {};
      for (const f of findings) { bySev[f.severity] = (bySev[f.severity] || 0) + 1; }
      const sevStr = Object.entries(bySev).map(([s, n]) => {
        const sc = severityColor(s);
        return `${sc}${n} ${s}${c.reset}`;
      }).join(', ');
      console.log(`${icons.caution}  ${c.bold}${slug}${c.reset}  ${findings.length} findings (${sevStr})  ${c.dim}${duration}${c.reset}`);
      for (const f of findings) {
        const sc = severityColor(f.severity);
        console.log(`   ${severityIcon(f.severity)} ${sc}${f.severity.toUpperCase().padEnd(8)}${c.reset} ${f.title}  ${c.dim}${f.file}:${f.line}${c.reset}`);
      }
    } else {
      console.log(`${icons.safe}  ${c.bold}${slug}${c.reset}  ${c.green}clean${c.reset}  ${c.dim}${files.length} files, ${duration}${c.reset}`);
    }
    return;
  }
  
  // Header
  console.log(`${icons.scan}  ${c.bold}${slug}${c.reset}  ${c.dim}${url}${c.reset}`);
  console.log(`${icons.pipe}  ${c.dim}${info.language} ${info.type}${c.reset}  ${c.dim}${files.length} files scanned in ${duration}${c.reset}`);
  
  // Tools & prompts tree
  const items = [
    ...info.tools.map(t => ({ kind: 'tool', name: t })),
    ...info.prompts.map(p => ({ kind: 'prompt', name: p })),
  ];
  
  if (items.length > 0) {
    console.log(`${icons.pipe}`);
    for (let i = 0; i < items.length; i++) {
      const isLast = i === items.length - 1 && findings.length === 0;
      const branch = isLast ? icons.treeLast : icons.tree;
      const item = items[i];
      const kindLabel = item.kind === 'tool' ? `${c.dim}tool${c.reset}  ` : `${c.dim}prompt${c.reset}`;
      const padName = item.name.padEnd(28);
      
      // Check if this tool has a finding associated
      const toolFinding = findings.find(f => 
        f.snippet && f.snippet.toLowerCase().includes(item.name.toLowerCase())
      );
      
      if (toolFinding) {
        const sc = severityColor(toolFinding.severity);
        console.log(`${branch}  ${kindLabel}  ${c.bold}${padName}${c.reset} ${sc}⚠ flagged${c.reset} — ${toolFinding.title}`);
      } else {
        console.log(`${branch}  ${kindLabel}  ${c.bold}${padName}${c.reset} ${c.green}✔ ok${c.reset}`);
      }
    }
  } else {
    console.log(`${icons.pipe}  ${c.dim}(no tools or prompts detected)${c.reset}`);
  }
  
  // Findings with severity stripe
  if (findings.length > 0) {
    console.log();
    console.log(sectionHeader(`Findings (${findings.length})`));
    console.log(`  ${c.dim}static analysis — may include false positives${c.reset}`);
    console.log();
    for (const f of findings) {
      const sc = severityColor(f.severity);
      console.log(`  ${sc}┃${c.reset} ${sc}${f.severity.toUpperCase().padEnd(8)}${c.reset}  ${c.bold}${f.title}${c.reset}`);
      console.log(`  ${sc}┃${c.reset}           ${c.dim}${f.file}:${f.line}${c.reset}  ${c.dim}${f.snippet || ''}${c.reset}`);
    }

    // Severity histogram
    const histLines = severityHistogram(findings);
    if (histLines.length > 1) {
      console.log();
      console.log(sectionHeader('Severity'));
      for (const line of histLines) console.log(line);
    }
  }

  // Registry status
  console.log();
  console.log(sectionHeader('Registry'));
  if (registryData) {
    const rd = registryData;
    const riskScore = rd.risk_score ?? rd.latest_risk_score ?? 0;
    console.log(`  ${riskBadge(riskScore)}  ${c.dim}${REGISTRY_URL}/packages/${slug}${c.reset}`);
  } else {
    console.log(`  ${c.dim}not audited yet${c.reset}`);
  }

  console.log();
}

function printSummary(results) {
  const total = results.length;
  const safe = results.filter(r => r.findings.length === 0).length;
  const withFindings = total - safe;
  const totalFindings = results.reduce((sum, r) => sum + r.findings.length, 0);
  const allFindings = results.flatMap(r => r.findings);

  console.log(sectionHeader(`Summary — ${total} packages scanned`));
  console.log();
  if (safe > 0) console.log(`  ${icons.safe}  ${c.green}${safe} clean${c.reset}`);
  if (withFindings > 0) console.log(`  ${icons.caution}  ${c.yellow}${withFindings} with findings${c.reset} (${totalFindings} total)`);
  console.log();
  console.log(`  ${coverageBar(safe, total)}`);

  // Severity histogram
  const histLines = severityHistogram(allFindings);
  if (histLines.length > 0) {
    console.log();
    console.log(sectionHeader('Severity'));
    for (const line of histLines) console.log(line);
  }

  console.log();
}

// ── Clone & Scan ────────────────────────────────────────

async function scanRepo(url) {
  const start = Date.now();
  const slug = slugFromUrl(url);
  
  if (!jsonMode) process.stdout.write(`${icons.scan}  Scanning ${c.bold}${slug}${c.reset} ${c.dim}...${c.reset}`);
  
  // Clone
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'agentaudit-'));
  const repoPath = path.join(tmpDir, 'repo');
  try {
    safeGitClone(url, repoPath);
  } catch (err) {
    if (!jsonMode) {
      process.stdout.write(`  ${c.red}✖ clone failed${c.reset}\n`);
      const msg = err.stderr?.toString().trim() || err.message?.split('\n')[0] || '';
      if (msg) console.log(`    ${c.dim}${msg}${c.reset}`);
      console.log(`    ${c.dim}Make sure git is installed and the URL is accessible.${c.reset}`);
    }
    return null;
  }
  
  // Collect files
  const files = collectFiles(repoPath);
  
  // Detect info
  const info = detectPackageInfo(repoPath, files);
  
  // Quick checks
  const findings = quickChecks(files);
  
  // Registry lookup
  const registryData = await checkRegistry(slug);
  
  // Cleanup
  try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
  
  const duration = elapsed(start);
  
  if (!jsonMode) {
    // Clear the "Scanning..." line
    process.stdout.write('\r\x1b[K');
    
    // Print result
    printScanResult(url, info, files, findings, registryData, duration);
  }
  
  return { slug, url, info, files: files.length, findings, registryData, duration };
}

// ── Discover local MCP configs ──────────────────────────

/**
 * Minimal YAML parser — extracts MCP server list entries from
 * Continue.dev (mcpServers: list) and Goose (extensions: list).
 * Zero dependencies. Only handles the subset of YAML used by these tools.
 */
function parseSimpleYaml(text, rootKey) {
  const result = { mcpServers: {} };
  const lines = text.split('\n');
  let inSection = false;
  let currentName = null;
  let currentServer = {};
  let collectingArgs = false;
  let argsIndent = -1;

  for (const line of lines) {
    const trimmed = line.trimEnd();
    if (trimmed === '' || /^\s*#/.test(trimmed)) continue;
    const indent = line.search(/\S/);

    if (indent === 0 && trimmed === rootKey + ':') { inSection = true; continue; }
    if (indent === 0 && inSection && /^\w/.test(trimmed)) {
      if (currentName) result.mcpServers[currentName] = currentServer;
      break;
    }
    if (!inSection) continue;

    const nameMatch = trimmed.match(/^\s*-\s+name:\s*(.+)/);
    if (nameMatch) {
      if (currentName) result.mcpServers[currentName] = currentServer;
      currentName = nameMatch[1].replace(/^["']|["']$/g, '');
      currentServer = {};
      collectingArgs = false;
      continue;
    }

    if (collectingArgs && indent > argsIndent) {
      const argVal = trimmed.match(/^\s*-\s+(.+)/);
      if (argVal) {
        if (!currentServer.args) currentServer.args = [];
        currentServer.args.push(argVal[1].replace(/^["']|["']$/g, ''));
        continue;
      }
    }
    if (collectingArgs && indent <= argsIndent) collectingArgs = false;
    if (!currentName) continue;

    const kvMatch = trimmed.match(/^\s+(command|cmd|type|url):\s*(.+)/);
    if (kvMatch) {
      collectingArgs = false;
      const key = kvMatch[1] === 'cmd' ? 'command' : kvMatch[1];
      currentServer[key] = kvMatch[2].replace(/^["']|["']$/g, '');
      continue;
    }

    const argsMatch = trimmed.match(/^\s+(args):\s*(.*)/);
    if (argsMatch) {
      const inlineArr = argsMatch[2].match(/^\[(.+)\]$/);
      if (inlineArr) {
        currentServer.args = inlineArr[1].split(',').map(s => s.trim().replace(/^["']|["']$/g, ''));
        collectingArgs = false;
      } else {
        collectingArgs = true;
        argsIndent = indent;
        currentServer.args = [];
      }
      continue;
    }
  }
  if (currentName) result.mcpServers[currentName] = currentServer;
  return result;
}

/**
 * Minimal TOML parser — extracts [mcp_servers.xxx] sections
 * from OpenAI Codex CLI config. Zero dependencies.
 */
function parseSimpleToml(text) {
  const result = { mcpServers: {} };
  const lines = text.split('\n');
  let currentName = null;
  let currentServer = {};

  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed === '' || trimmed.startsWith('#')) continue;

    const sectionMatch = trimmed.match(/^\[mcp_servers\.(.+)\]$/);
    if (sectionMatch) {
      if (currentName) result.mcpServers[currentName] = currentServer;
      currentName = sectionMatch[1];
      currentServer = {};
      continue;
    }
    if (trimmed.startsWith('[') && !trimmed.startsWith('[mcp_servers.')) {
      if (currentName) result.mcpServers[currentName] = currentServer;
      currentName = null;
      continue;
    }
    if (!currentName) continue;

    const strMatch = trimmed.match(/^(command|url)\s*=\s*"(.+?)"/);
    if (strMatch) { currentServer[strMatch[1]] = strMatch[2]; continue; }

    const argsMatch = trimmed.match(/^args\s*=\s*\[(.+)\]/);
    if (argsMatch) {
      currentServer.args = argsMatch[1].split(',').map(s => s.trim().replace(/^["']|["']$/g, ''));
      continue;
    }

    const boolMatch = trimmed.match(/^enabled\s*=\s*(true|false)/);
    if (boolMatch && boolMatch[1] === 'false') currentServer.disabled = true;
  }
  if (currentName) result.mcpServers[currentName] = currentServer;
  return result;
}

/**
 * Comprehensive MCP config discovery across all major AI editors & tools.
 *
 * Supports: Claude Desktop, Claude Code, Cursor, Windsurf, VS Code,
 * Cline, Roo Code, Amazon Q, Gemini CLI, Zed, Continue.dev, Goose,
 * OpenAI Codex CLI, Visual Studio — global + project-level configs.
 */
function findMcpConfigs() {
  const home = process.env.HOME || process.env.USERPROFILE || '';
  const platform = process.platform;
  const cwd = process.cwd();
  const xdgConfig = process.env.XDG_CONFIG_HOME || path.join(home, '.config');

  // Platform-specific app data directory
  // macOS: ~/Library/Application Support, Windows: ~/AppData/Roaming, Linux: ~/.config
  const appData = platform === 'darwin'
    ? path.join(home, 'Library', 'Application Support')
    : platform === 'win32'
    ? path.join(home, 'AppData', 'Roaming')
    : xdgConfig;

  // Each candidate: { name, path, format: 'json'|'yaml'|'toml', key: top-level key }
  const candidates = [
    // ── Claude Desktop ──
    ...(platform === 'darwin' ? [{ name: 'Claude Desktop', path: path.join(home, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json'), format: 'json', key: 'mcpServers' }] : []),
    ...(platform === 'win32'  ? [{ name: 'Claude Desktop', path: path.join(home, 'AppData', 'Roaming', 'Claude', 'claude_desktop_config.json'), format: 'json', key: 'mcpServers' }] : []),
    ...(platform === 'linux'  ? [{ name: 'Claude Desktop', path: path.join(xdgConfig, 'Claude', 'claude_desktop_config.json'), format: 'json', key: 'mcpServers' }] : []),

    // ── Claude Code ──
    { name: 'Claude Code', path: path.join(home, '.claude.json'), format: 'json', key: 'mcpServers' },
    { name: 'Claude Code', path: path.join(home, '.claude', 'mcp.json'), format: 'json', key: 'mcpServers' },

    // ── Cursor (global) ──
    { name: 'Cursor', path: path.join(home, '.cursor', 'mcp.json'), format: 'json', key: 'mcpServers' },

    // ── Windsurf / Codeium ──
    { name: 'Windsurf', path: path.join(home, '.codeium', 'windsurf', 'mcp_config.json'), format: 'json', key: 'mcpServers' },

    // ── VS Code (global mcp.json — uses 'servers' key) ──
    ...(platform === 'darwin' ? [{ name: 'VS Code', path: path.join(home, 'Library', 'Application Support', 'Code', 'User', 'mcp.json'), format: 'json', key: 'servers' }] : []),
    ...(platform === 'win32'  ? [{ name: 'VS Code', path: path.join(home, 'AppData', 'Roaming', 'Code', 'User', 'mcp.json'), format: 'json', key: 'servers' }] : []),
    ...(platform === 'linux'  ? [{ name: 'VS Code', path: path.join(xdgConfig, 'Code', 'User', 'mcp.json'), format: 'json', key: 'servers' }] : []),

    // ── VS Code settings.json (mcp.servers nested key) ──
    ...(platform === 'darwin' ? [{ name: 'VS Code (settings)', path: path.join(home, 'Library', 'Application Support', 'Code', 'User', 'settings.json'), format: 'json', key: 'mcp.servers' }] : []),
    ...(platform === 'win32'  ? [{ name: 'VS Code (settings)', path: path.join(home, 'AppData', 'Roaming', 'Code', 'User', 'settings.json'), format: 'json', key: 'mcp.servers' }] : []),
    ...(platform === 'linux'  ? [{ name: 'VS Code (settings)', path: path.join(xdgConfig, 'Code', 'User', 'settings.json'), format: 'json', key: 'mcp.servers' }] : []),

    // ── Cline (VS Code extension) ──
    ...(platform === 'darwin' ? [{ name: 'Cline', path: path.join(home, 'Library', 'Application Support', 'Code', 'User', 'globalStorage', 'saoudrizwan.claude-dev', 'settings', 'cline_mcp_settings.json'), format: 'json', key: 'mcpServers' }] : []),
    ...(platform === 'win32'  ? [{ name: 'Cline', path: path.join(home, 'AppData', 'Roaming', 'Code', 'User', 'globalStorage', 'saoudrizwan.claude-dev', 'settings', 'cline_mcp_settings.json'), format: 'json', key: 'mcpServers' }] : []),
    ...(platform === 'linux'  ? [{ name: 'Cline', path: path.join(xdgConfig, 'Code', 'User', 'globalStorage', 'saoudrizwan.claude-dev', 'settings', 'cline_mcp_settings.json'), format: 'json', key: 'mcpServers' }] : []),

    // ── Roo Code (VS Code extension) ──
    ...(platform === 'darwin' ? [{ name: 'Roo Code', path: path.join(home, 'Library', 'Application Support', 'Code', 'User', 'globalStorage', 'rooveterinaryinc.roo-cline', 'settings', 'mcp_settings.json'), format: 'json', key: 'mcpServers' }] : []),
    ...(platform === 'win32'  ? [{ name: 'Roo Code', path: path.join(home, 'AppData', 'Roaming', 'Code', 'User', 'globalStorage', 'rooveterinaryinc.roo-cline', 'settings', 'mcp_settings.json'), format: 'json', key: 'mcpServers' }] : []),
    ...(platform === 'linux'  ? [{ name: 'Roo Code', path: path.join(xdgConfig, 'Code', 'User', 'globalStorage', 'rooveterinaryinc.roo-cline', 'settings', 'mcp_settings.json'), format: 'json', key: 'mcpServers' }] : []),

    // ── Amazon Q Developer ──
    { name: 'Amazon Q', path: path.join(home, '.aws', 'amazonq', 'mcp.json'), format: 'json', key: 'mcpServers' },
    { name: 'Amazon Q (IDE)', path: path.join(home, '.aws', 'amazonq', 'default.json'), format: 'json', key: 'mcpServers' },

    // ── Gemini CLI ──
    { name: 'Gemini CLI', path: path.join(home, '.gemini', 'settings.json'), format: 'json', key: 'mcpServers' },

    // ── Zed (macOS + Linux only, uses 'context_servers' key) ──
    ...(platform === 'darwin' ? [{ name: 'Zed', path: path.join(home, '.zed', 'settings.json'), format: 'json', key: 'context_servers' }] : []),
    ...(platform === 'linux'  ? [{ name: 'Zed', path: path.join(xdgConfig, 'zed', 'settings.json'), format: 'json', key: 'context_servers' }] : []),

    // ── Continue.dev ──
    { name: 'Continue', path: path.join(home, '.continue', 'config.json'), format: 'json', key: 'mcpServers' },
    { name: 'Continue', path: path.join(home, '.continue', 'config.yaml'), format: 'yaml', key: 'mcpServers' },

    // ── Goose (Block/Square) ──
    { name: 'Goose', path: path.join(xdgConfig, 'goose', 'config.yaml'), format: 'yaml', key: 'extensions' },

    // ── OpenAI Codex CLI ──
    { name: 'Codex CLI', path: path.join(home, '.codex', 'config.toml'), format: 'toml', key: 'mcp_servers' },

    // ── Visual Studio (Windows only) ──
    ...(platform === 'win32' ? [{ name: 'Visual Studio', path: path.join(home, '.mcp.json'), format: 'json', key: 'mcpServers' }] : []),

    // ── Project-level configs (cwd) ──
    { name: 'Claude Code (project)', path: path.join(cwd, '.mcp.json'), format: 'json', key: 'mcpServers' },
    { name: 'Cursor (project)', path: path.join(cwd, '.cursor', 'mcp.json'), format: 'json', key: 'mcpServers' },
    { name: 'VS Code (project)', path: path.join(cwd, '.vscode', 'mcp.json'), format: 'json', key: 'servers' },
    { name: 'Roo Code (project)', path: path.join(cwd, '.roo', 'mcp.json'), format: 'json', key: 'mcpServers' },
    { name: 'Amazon Q (project)', path: path.join(cwd, '.amazonq', 'mcp.json'), format: 'json', key: 'mcpServers' },
    { name: 'Gemini CLI (project)', path: path.join(cwd, '.gemini', 'settings.json'), format: 'json', key: 'mcpServers' },
    ...(platform !== 'win32' ? [{ name: 'Zed (project)', path: path.join(cwd, '.zed', 'settings.json'), format: 'json', key: 'context_servers' }] : []),
    { name: 'Codex CLI (project)', path: path.join(cwd, '.codex', 'config.toml'), format: 'toml', key: 'mcp_servers' },
  ];

  // Test config override
  if (process.env.AGENTAUDIT_TEST_CONFIG) {
    candidates.push({ name: 'Test Config', path: process.env.AGENTAUDIT_TEST_CONFIG, format: 'json', key: 'mcpServers' });
  }

  // Continue.dev mcpServers drop-in directory (individual JSON files)
  const continueDropIn = path.join(home, '.continue', 'mcpServers');
  try {
    if (fs.existsSync(continueDropIn)) {
      for (const f of fs.readdirSync(continueDropIn)) {
        if (f.endsWith('.json')) {
          candidates.push({ name: 'Continue (drop-in)', path: path.join(continueDropIn, f), format: 'json', key: 'mcpServers' });
        }
      }
    }
  } catch {}

  // Project-level Continue.dev drop-ins
  const cwdContinueDropIn = path.join(cwd, '.continue', 'mcpServers');
  try {
    if (fs.existsSync(cwdContinueDropIn)) {
      for (const f of fs.readdirSync(cwdContinueDropIn)) {
        if (f.endsWith('.json')) {
          candidates.push({ name: 'Continue (project drop-in)', path: path.join(cwdContinueDropIn, f), format: 'json', key: 'mcpServers' });
        }
      }
    }
  } catch {}

  const found = [];
  const seenPaths = new Set();

  for (const c of candidates) {
    const resolved = path.resolve(c.path);
    if (seenPaths.has(resolved)) continue;
    if (!fs.existsSync(c.path)) continue;
    seenPaths.add(resolved);

    try {
      const raw = fs.readFileSync(c.path, 'utf8');
      let content;

      if (c.format === 'yaml') {
        content = parseSimpleYaml(raw, c.key);
      } else if (c.format === 'toml') {
        content = parseSimpleToml(raw);
      } else {
        content = JSON.parse(raw);
        // Normalize different JSON key structures to mcpServers
        if (c.key === 'mcp.servers' && content.mcp?.servers) {
          content = { mcpServers: content.mcp.servers };
        } else if (c.key === 'context_servers' && content.context_servers) {
          // Zed: normalize nested { command: { path, args } } → { command, args }
          const normalized = {};
          for (const [name, cfg] of Object.entries(content.context_servers)) {
            if (cfg.command && typeof cfg.command === 'object') {
              normalized[name] = { command: cfg.command.path || cfg.command.command, args: cfg.command.args || [], env: cfg.command.env || {} };
            } else {
              normalized[name] = cfg;
            }
          }
          content = { mcpServers: normalized };
        } else if (c.key === 'servers' && content.servers && !content.mcpServers) {
          content = { mcpServers: content.servers };
        }
      }

      // Only include configs that actually have servers
      const servers = content?.mcpServers || content?.servers || {};
      if (Object.keys(servers).length > 0) {
        found.push({ name: c.name, path: c.path, content });
      }
    } catch {}
  }

  return found;
}

// ── Skill Discovery & Validation ─────────────────────────

/**
 * Parse YAML frontmatter from a SKILL.md file.
 * Returns { meta: {...}, body: string, errors: string[] }
 */
function parseSkillFrontmatter(content) {
  const errors = [];
  const lines = content.split('\n');

  // Must start with ---
  if (lines[0].trim() !== '---') {
    return { meta: null, body: content, errors: ['Missing YAML frontmatter (file must start with ---)'] };
  }

  // Find closing ---
  let endIdx = -1;
  for (let i = 1; i < lines.length; i++) {
    if (lines[i].trim() === '---') { endIdx = i; break; }
  }
  if (endIdx === -1) {
    return { meta: null, body: content, errors: ['Unclosed frontmatter (missing closing ---)'] };
  }

  // Parse YAML-like key: value pairs
  const meta = {};
  const yamlLines = lines.slice(1, endIdx);
  for (let i = 0; i < yamlLines.length; i++) {
    const line = yamlLines[i];
    if (line.trim() === '' || line.trim().startsWith('#')) continue;

    // Check for tabs
    if (line.includes('\t')) {
      errors.push(`Line ${i + 2}: Tab character found (use spaces)`);
    }

    const match = line.match(/^([a-z][a-z0-9_-]*):\s*(.*)/i);
    if (!match) {
      // Could be a continuation line (YAML multiline)
      continue;
    }
    const key = match[1].toLowerCase();
    let value = match[2].trim();

    // Handle YAML lists on next lines
    if (value === '' && i + 1 < yamlLines.length && yamlLines[i + 1].match(/^\s+-\s/)) {
      const items = [];
      let j = i + 1;
      while (j < yamlLines.length && yamlLines[j].match(/^\s+-\s/)) {
        items.push(yamlLines[j].replace(/^\s+-\s*/, '').trim());
        j++;
      }
      value = items;
    }

    // Strip surrounding quotes
    if (typeof value === 'string' && ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'")))) {
      value = value.slice(1, -1);
    }

    meta[key] = value;
  }

  const body = lines.slice(endIdx + 1).join('\n').trim();
  return { meta, body, errors };
}

/**
 * Validate a parsed skill against the Claude Code SKILL.md spec.
 * Returns { errors: [...], warnings: [...], info: {...} }
 */
function validateSkill(parsed) {
  const { meta, body, errors: parseErrors } = parsed;
  const errors = [...parseErrors];
  const warnings = [];
  const info = {};

  if (!meta) return { errors, warnings, info };

  // Known fields
  const knownFields = new Set([
    'name', 'description', 'allowed-tools', 'user-invocable', 'user-invokable',
    'disable-model-invocation', 'license', 'metadata', 'argument-hint',
    'compatibility', 'version', 'author',
  ]);

  // Check for unknown fields
  for (const key of Object.keys(meta)) {
    if (!knownFields.has(key)) {
      warnings.push(`Unknown frontmatter field: "${key}"`);
    }
  }

  // Required: name
  if (!meta.name) {
    errors.push('Missing required field: name');
  } else {
    info.name = meta.name;
    if (meta.name.length > 64) errors.push(`name exceeds 64 chars (${meta.name.length})`);
    if (/<[^>]+>/.test(meta.name)) errors.push('name contains XML/HTML tags');
  }

  // Required: description
  if (!meta.description) {
    errors.push('Missing required field: description');
  } else {
    info.description = typeof meta.description === 'string' ? meta.description.slice(0, 120) : String(meta.description).slice(0, 120);
    if (typeof meta.description === 'string' && meta.description.length > 1024) {
      warnings.push(`description is ${meta.description.length} chars (recommended max: 1024)`);
    }
    if (/<[^>]+>/.test(meta.description)) warnings.push('description contains XML/HTML tags');
  }

  // Security: allowed-tools
  if (!meta['allowed-tools']) {
    warnings.push('No allowed-tools set — skill has access to ALL tools (security risk)');
    info.allowedTools = null;
  } else {
    const tools = typeof meta['allowed-tools'] === 'string'
      ? meta['allowed-tools'].split(',').map(t => t.trim()).filter(Boolean)
      : Array.isArray(meta['allowed-tools']) ? meta['allowed-tools'] : [];
    info.allowedTools = tools;
    // Check for wildcard/dangerous patterns
    if (tools.some(t => t === '*' || t === 'Bash' || t === 'Bash(*)')) {
      warnings.push('allowed-tools includes unrestricted Bash access');
    }
  }

  // Boolean fields
  for (const boolField of ['user-invocable', 'user-invokable', 'disable-model-invocation']) {
    if (meta[boolField] !== undefined) {
      const val = String(meta[boolField]).toLowerCase();
      if (!['true', 'false'].includes(val)) {
        errors.push(`${boolField} must be true or false (got: "${meta[boolField]}")`);
      }
    }
  }

  // Typo detection
  if (meta['user-invokable'] && !meta['user-invocable']) {
    warnings.push('Using "user-invokable" (known typo variant) — both spellings work');
  }

  // Body checks
  if (body) {
    const bodyLines = body.split('\n').length;
    info.bodyLines = bodyLines;
    if (bodyLines > 500) warnings.push(`Body is ${bodyLines} lines (recommended max: 500)`);

    // Check for potential prompt injection patterns in body
    const injectionPatterns = [
      { pattern: /ignore\s+(all\s+)?previous\s+(instructions|rules)/i, label: 'Prompt injection pattern' },
      { pattern: /<IMPORTANT>/i, label: 'Suspicious <IMPORTANT> tag' },
      { pattern: /system\s*:\s*you\s+are/i, label: 'System prompt override attempt' },
    ];
    for (const { pattern, label } of injectionPatterns) {
      if (pattern.test(body)) {
        warnings.push(`${label} detected in body`);
      }
    }
  }

  // Extract MCP tool references
  const mcpRefs = [];
  const mcpPattern = /mcp__([a-z0-9_-]+)__([a-z0-9_]+)/gi;
  const fullText = (meta.description || '') + ' ' + (typeof meta['allowed-tools'] === 'string' ? meta['allowed-tools'] : '') + ' ' + (body || '');
  let mcpMatch;
  while ((mcpMatch = mcpPattern.exec(fullText)) !== null) {
    mcpRefs.push({ server: mcpMatch[1], tool: mcpMatch[2] });
  }
  info.mcpRefs = mcpRefs;

  // Deduplicate MCP server names
  info.mcpServers = [...new Set(mcpRefs.map(r => r.server))];

  return { errors, warnings, info };
}

/**
 * Find all SKILL.md files in known skill directories.
 */
function findSkills() {
  const home = process.env.HOME || process.env.USERPROFILE || '';
  const cwd = process.cwd();
  const found = [];

  const skillDirs = [
    // Global skill dirs
    { name: 'Claude Code (global)', base: path.join(home, '.claude', 'skills') },
    { name: 'Cursor (global)', base: path.join(home, '.cursor', 'skills') },
    { name: 'Antigravity (global)', base: path.join(home, '.agent', 'skills') },
    // Project-level skill dirs
    { name: 'Claude Code (project)', base: path.join(cwd, '.claude', 'skills') },
    { name: 'Cursor (project)', base: path.join(cwd, '.cursor', 'skills') },
    { name: 'GitHub Skills (project)', base: path.join(cwd, '.github', 'skills') },
    { name: 'Antigravity (project)', base: path.join(cwd, '.agent', 'skills') },
  ];

  for (const dir of skillDirs) {
    if (!fs.existsSync(dir.base)) continue;
    try {
      const entries = fs.readdirSync(dir.base, { withFileTypes: true });
      for (const entry of entries) {
        if (!entry.isDirectory() && !entry.isSymbolicLink()) continue;
        const skillPath = path.join(dir.base, entry.name, 'SKILL.md');
        if (!fs.existsSync(skillPath)) continue;
        try {
          const content = fs.readFileSync(skillPath, 'utf8');
          const parsed = parseSkillFrontmatter(content);
          const validation = validateSkill(parsed);
          found.push({
            source: dir.name,
            dir: path.join(dir.base, entry.name),
            path: skillPath,
            dirName: entry.name,
            parsed,
            validation,
            isSymlink: entry.isSymbolicLink(),
          });
        } catch {}
      }
    } catch {}
  }

  return found;
}

// ── Server Config Extraction ─────────────────────────────

function extractServersFromConfig(config) {
  // Handle both { mcpServers: {...} } and { servers: {...} } formats
  const servers = config.mcpServers || config.servers || {};
  const result = [];
  
  for (const [name, serverConfig] of Object.entries(servers)) {
    const info = {
      name,
      command: serverConfig.command || null,
      args: serverConfig.args || [],
      url: serverConfig.url || null,
      sourceUrl: null,
    };
    
    // Try to extract source URL from args (common patterns)
    const allArgs = [info.command, ...info.args].filter(Boolean).join(' ');
    
    // npx package-name → npm package
    const npxMatch = allArgs.match(/npx\s+(?:-y\s+)?(@?[a-z0-9][\w./-]*)/i);
    if (npxMatch) info.npmPackage = npxMatch[1];
    
    // node /path/to/something → try to find package.json
    const nodePathMatch = allArgs.match(/node\s+["']?([^"'\s]+)/);
    if (nodePathMatch) {
      const scriptPath = nodePathMatch[1];
      // Walk up to find package.json with repository
      let dir = path.dirname(path.resolve(scriptPath));
      for (let i = 0; i < 5; i++) {
        const pkgPath = path.join(dir, 'package.json');
        if (fs.existsSync(pkgPath)) {
          try {
            const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
            if (pkg.repository?.url) {
              info.sourceUrl = pkg.repository.url.replace(/^git\+/, '').replace(/\.git$/, '');
            }
            if (pkg.name) info.npmPackage = pkg.name;
          } catch {}
          break;
        }
        const parent = path.dirname(dir);
        if (parent === dir) break;
        dir = parent;
      }
    }
    
    // python/uvx with package name
    const pyMatch = allArgs.match(/(?:uvx|pip run|python -m)\s+(@?[a-z0-9][\w./-]*)/i);
    if (pyMatch) info.pyPackage = pyMatch[1];
    
    // URL-based MCP server (remote HTTP)
    if (info.url && !info.npmPackage && !info.pyPackage) {
      try {
        const parsed = new URL(info.url);
        // Extract service name from hostname: mcp.supabase.com → supabase
        const hostParts = parsed.hostname.split('.');
        if (hostParts.length >= 2) {
          const serviceName = hostParts.length === 3 ? hostParts[1] : hostParts[0];
          info.remoteService = serviceName;
        }
      } catch {}
    }

    // Resolve local installation directory
    info.localDir = resolveLocalDir(info);

    result.push(info);
  }
  return result;
}

function serverSlug(server) {
  // Try to derive a slug for registry lookup
  if (server.npmPackage) return server.npmPackage.replace(/^@/, '').replace(/\//g, '-');
  if (server.pyPackage) return server.pyPackage.replace(/[^a-z0-9-]/gi, '-');
  return server.name.toLowerCase().replace(/[^a-z0-9-]/gi, '-');
}

/**
 * Resolve the local installation directory for a discovered MCP server.
 * Returns an absolute path or null if not found.
 */
function resolveLocalDir(server) {
  const home = os.homedir();
  const isWin = process.platform === 'win32';

  // node /path/to/file → walk up to project root (package.json or .git)
  const allArgs = [server.command, ...server.args].filter(Boolean).join(' ');
  const nodePathMatch = allArgs.match(/node\s+["']?([^"'\s]+)/);
  if (nodePathMatch) {
    let dir = path.dirname(path.resolve(nodePathMatch[1]));
    for (let i = 0; i < 5; i++) {
      if (fs.existsSync(path.join(dir, 'package.json')) || fs.existsSync(path.join(dir, '.git'))) return dir;
      const parent = path.dirname(dir);
      if (parent === dir) break;
      dir = parent;
    }
    // Fallback: use the script's directory
    return path.dirname(path.resolve(nodePathMatch[1]));
  }

  // python /path/to/file → same approach
  const pyPathMatch = allArgs.match(/python[3]?\s+["']?([^"'\s]+\.py)/);
  if (pyPathMatch) {
    let dir = path.dirname(path.resolve(pyPathMatch[1]));
    for (let i = 0; i < 5; i++) {
      if (fs.existsSync(path.join(dir, 'pyproject.toml')) || fs.existsSync(path.join(dir, 'setup.py')) || fs.existsSync(path.join(dir, '.git'))) return dir;
      const parent = path.dirname(dir);
      if (parent === dir) break;
      dir = parent;
    }
    return path.dirname(path.resolve(pyPathMatch[1]));
  }

  // npm/npx package → check global node_modules
  if (server.npmPackage) {
    const pkgName = server.npmPackage.replace(/@latest$/, '').replace(/@[\d.]+$/, '');
    const candidates = [];
    // Global npm
    try {
      const globalRoot = execFileSync('npm', ['root', '-g'], { timeout: 5000, stdio: 'pipe' }).toString().trim();
      candidates.push(path.join(globalRoot, pkgName));
    } catch {}
    // Local node_modules (cwd)
    candidates.push(path.join(process.cwd(), 'node_modules', pkgName));
    for (const dir of candidates) {
      if (fs.existsSync(dir)) return dir;
    }
  }

  // uvx/pip package → check uv tools cache and site-packages
  if (server.pyPackage) {
    const pkgName = server.pyPackage.replace(/@latest$/, '').replace(/@[\d.]+$/, '');
    const candidates = [];
    if (isWin) {
      const localAppData = process.env.LOCALAPPDATA || path.join(home, 'AppData', 'Local');
      candidates.push(path.join(localAppData, 'uv', 'tools', pkgName));
    } else {
      candidates.push(path.join(home, '.local', 'share', 'uv', 'tools', pkgName));
    }
    // Also try pip show
    try {
      const pipOut = execFileSync('pip', ['show', pkgName, '-f'], { timeout: 5000, stdio: 'pipe' }).toString();
      const locMatch = pipOut.match(/Location:\s*(.+)/);
      if (locMatch) {
        const normalized = pkgName.replace(/-/g, '_');
        const pkgDir = path.join(locMatch[1].trim(), normalized);
        if (fs.existsSync(pkgDir)) candidates.push(pkgDir);
      }
    } catch {}
    for (const dir of candidates) {
      if (fs.existsSync(dir)) return dir;
    }
  }

  return null;
}

/**
 * Scan a local directory (like scanRepo but without cloning).
 */
async function scanLocalDir(localDir, serverName) {
  const start = Date.now();
  const slug = serverName.toLowerCase().replace(/[^a-z0-9-]/gi, '-');

  if (!jsonMode) process.stdout.write(`${icons.scan}  Scanning ${c.bold}${slug}${c.reset} ${c.dim}(local)${c.reset} ${c.dim}...${c.reset}`);

  // Collect files from local dir
  const files = collectFiles(localDir);
  if (files.length === 0) {
    if (!jsonMode) process.stdout.write(`  ${c.yellow}no scannable files found${c.reset}\n`);
    return null;
  }

  // Detect info
  const info = detectPackageInfo(localDir, files);

  // Quick checks
  const findings = quickChecks(files);

  // Registry lookup
  const registryData = await checkRegistry(slug);

  const duration = elapsed(start);

  if (!jsonMode) {
    process.stdout.write('\r\x1b[K');
    printScanResult(`local://${localDir}`, info, files, findings, registryData, duration);
  }

  return { slug, url: `local://${localDir}`, info, files: files.length, findings, registryData, duration };
}

/**
 * Download package source from PyPI or npm to a temp dir and scan it.
 * Used as last resort when git clone fails and no local install exists.
 */
async function downloadAndScan(server) {
  const start = Date.now();
  const slug = server.name.toLowerCase().replace(/[^a-z0-9-]/gi, '-');
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'agentaudit-pkg-'));

  try {
    if (server.pyPackage) {
      const pkgName = server.pyPackage.replace(/@latest$/, '').replace(/@[\d.]+$/, '');
      if (!jsonMode) process.stdout.write(`${icons.scan}  Downloading ${c.bold}${pkgName}${c.reset} ${c.dim}from PyPI...${c.reset}`);
      // Download sdist/wheel without installing
      execFileSync('pip', ['download', '--no-deps', '-d', tmpDir, pkgName], { timeout: 30000, stdio: 'pipe' });
      // Extract any .tar.gz or .whl (zip) files
      const downloaded = fs.readdirSync(tmpDir);
      const extractDir = path.join(tmpDir, 'src');
      fs.mkdirSync(extractDir, { recursive: true });
      for (const f of downloaded) {
        const fp = path.join(tmpDir, f);
        if (f.endsWith('.whl') || f.endsWith('.zip')) {
          execFileSync('python', ['-m', 'zipfile', '-e', fp, extractDir], { timeout: 10000, stdio: 'pipe' });
        } else if (f.endsWith('.tar.gz') || f.endsWith('.tgz')) {
          execFileSync('tar', ['xzf', fp, '-C', extractDir], { timeout: 10000, stdio: 'pipe' });
        }
      }
      const files = collectFiles(extractDir);
      if (files.length === 0) return null;
      const info = detectPackageInfo(extractDir, files);
      const findings = quickChecks(files);
      const registryData = await checkRegistry(slug);
      const duration = elapsed(start);
      if (!jsonMode) {
        process.stdout.write('\r\x1b[K');
        printScanResult(`pypi://${pkgName}`, info, files, findings, registryData, duration);
      }
      return { slug, url: `pypi://${pkgName}`, info, files: files.length, findings, registryData, duration };
    }

    if (server.npmPackage) {
      const pkgName = server.npmPackage.replace(/@latest$/, '').replace(/@[\d.]+$/, '');
      if (!jsonMode) process.stdout.write(`${icons.scan}  Downloading ${c.bold}${pkgName}${c.reset} ${c.dim}from npm...${c.reset}`);
      // npm pack downloads tarball without installing
      execFileSync('npm', ['pack', pkgName, '--pack-destination', tmpDir], { timeout: 30000, stdio: 'pipe' });
      const tarballs = fs.readdirSync(tmpDir).filter(f => f.endsWith('.tgz'));
      if (tarballs.length === 0) return null;
      const extractDir = path.join(tmpDir, 'src');
      fs.mkdirSync(extractDir, { recursive: true });
      execFileSync('tar', ['xzf', path.join(tmpDir, tarballs[0]), '-C', extractDir], { timeout: 10000, stdio: 'pipe' });
      const files = collectFiles(extractDir);
      if (files.length === 0) return null;
      const info = detectPackageInfo(extractDir, files);
      const findings = quickChecks(files);
      const registryData = await checkRegistry(slug);
      const duration = elapsed(start);
      if (!jsonMode) {
        process.stdout.write('\r\x1b[K');
        printScanResult(`npm://${pkgName}`, info, files, findings, registryData, duration);
      }
      return { slug, url: `npm://${pkgName}`, info, files: files.length, findings, registryData, duration };
    }
  } catch (err) {
    if (!jsonMode) {
      process.stdout.write('\r\x1b[K');
      process.stdout.write(`${icons.scan}  ${c.bold}${slug}${c.reset}  ${c.yellow}download failed${c.reset}\n`);
      const msg = err.stderr?.toString().trim().split('\n')[0] || err.message?.split('\n')[0] || '';
      if (msg) console.log(`    ${c.dim}${msg}${c.reset}`);
    }
  } finally {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
  }
  return null;
}

async function searchGitHub(query) {
  try {
    const res = await fetch(`https://api.github.com/search/repositories?q=${encodeURIComponent(query)}&per_page=1`, {
      signal: AbortSignal.timeout(5000),
      headers: { 'Accept': 'application/vnd.github+json' },
    });
    if (res.ok) {
      const data = await res.json();
      if (data.items?.length > 0) {
        return data.items[0].html_url;
      }
    }
  } catch {}
  return null;
}

async function resolveSourceUrl(server) {
  // Already have it
  if (server.sourceUrl) return server.sourceUrl;
  
  // Try npm registry
  if (server.npmPackage) {
    try {
      const res = await fetch(`https://registry.npmjs.org/${encodeURIComponent(server.npmPackage)}`, {
        signal: AbortSignal.timeout(5000),
      });
      if (res.ok) {
        const data = await res.json();
        let repoUrl = data.repository?.url;
        if (repoUrl) {
          repoUrl = repoUrl.replace(/^git\+/, '').replace(/\.git$/, '').replace(/^ssh:\/\/git@github\.com/, 'https://github.com');
          if (repoUrl.startsWith('http')) return repoUrl;
        }
      }
    } catch {}
    // Fallback: try GitHub search for the package name
    const ghUrl = await searchGitHub(server.npmPackage);
    if (ghUrl) return ghUrl;
    return `https://www.npmjs.com/package/${server.npmPackage}`;
  }
  
  // Try PyPI
  if (server.pyPackage) {
    try {
      const res = await fetch(`https://pypi.org/pypi/${encodeURIComponent(server.pyPackage)}/json`, {
        signal: AbortSignal.timeout(5000),
      });
      if (res.ok) {
        const data = await res.json();
        const urls = data.info?.project_urls || {};
        const source = urls.Source || urls.Repository || urls.Homepage || urls['Source Code'] || data.info?.home_page;
        if (source && source.startsWith('http')) return source;
      }
    } catch {}
    // Fallback: GitHub search
    const ghUrl = await searchGitHub(server.pyPackage);
    if (ghUrl) return ghUrl;
    return `https://pypi.org/project/${server.pyPackage}/`;
  }
  
  // URL-based remote MCP server — try GitHub search by service name
  if (server.remoteService) {
    // Try npm registry with common MCP naming patterns
    for (const tryName of [
      `@${server.remoteService}/mcp-server-${server.remoteService}`,
      `${server.remoteService}-mcp`,
      `mcp-server-${server.remoteService}`,
      server.remoteService,
    ]) {
      try {
        const res = await fetch(`https://registry.npmjs.org/${encodeURIComponent(tryName)}`, {
          signal: AbortSignal.timeout(3000),
        });
        if (res.ok) {
          const data = await res.json();
          let repoUrl = data.repository?.url;
          if (repoUrl) {
            repoUrl = repoUrl.replace(/^git\+/, '').replace(/\.git$/, '').replace(/^ssh:\/\/git@github\.com/, 'https://github.com');
            if (repoUrl.startsWith('http')) return repoUrl;
          }
        }
      } catch {}
    }
  }
  
  // Last resort: if server has a url, show it as context
  if (server.url) {
    try {
      const parsed = new URL(server.url);
      return `https://github.com/search?q=${encodeURIComponent(parsed.hostname + ' MCP')}&type=repositories`;
    } catch {}
  }
  
  return null;
}

async function discoverCommand(options = {}) {
  const autoScan = options.scan || false;
  const interactiveAudit = options.audit || false;
  
  if (!jsonMode) {
    console.log(`  ${c.bold}Discovering MCP servers across all AI tools...${c.reset}`);
    console.log();
  }
  
  const configs = findMcpConfigs();
  
  if (configs.length === 0) {
    console.log(`  ${c.yellow}No MCP configurations found.${c.reset}`);
    console.log(`  ${c.dim}Searched 15+ tools: Claude Desktop, Claude Code, Cursor, Windsurf, VS Code,${c.reset}`);
    console.log(`  ${c.dim}Cline, Roo Code, Amazon Q, Gemini CLI, Zed, Continue.dev, Goose, Codex CLI${c.reset}`);
    console.log();
    console.log(`  ${c.dim}Common MCP config locations:${c.reset}`);
    console.log(`  ${c.dim}  Claude Desktop:  ~/Library/Application Support/Claude/claude_desktop_config.json${c.reset}`);
    console.log(`  ${c.dim}  Claude Code:     ~/.claude.json${c.reset}`);
    console.log(`  ${c.dim}  Cursor:          ~/.cursor/mcp.json${c.reset}`);
    console.log(`  ${c.dim}  Windsurf:        ~/.codeium/windsurf/mcp_config.json${c.reset}`);
    console.log(`  ${c.dim}  VS Code:         (platform)/Code/User/mcp.json${c.reset}`);
    console.log(`  ${c.dim}  Project-level:   .mcp.json / .cursor/mcp.json / .vscode/mcp.json${c.reset}`);
    console.log();
    return;
  }
  
  let totalServers = 0;
  let checkedServers = 0;
  let auditedServers = 0;
  let unauditedServers = 0;
  const unauditedWithUrls = [];
  const allServersWithUrls = []; // For --scan: all servers we can scan
  
  for (const config of configs) {
    const servers = extractServersFromConfig(config.content);
    const serverCount = servers.length;
    totalServers += serverCount;
    
    const countLabel = serverCount === 0
      ? `${c.dim}no servers${c.reset}`
      : `found ${c.bold}${serverCount}${c.reset} server${serverCount > 1 ? 's' : ''}`;
    
    console.log(`${icons.bullet}  Scanning ${c.bold}${config.name}${c.reset}  ${c.dim}${config.path}${c.reset}    ${countLabel}`);
    
    if (serverCount === 0) {
      console.log();
      continue;
    }
    
    console.log();
    
    for (let i = 0; i < servers.length; i++) {
      const server = servers[i];
      const isLast = i === servers.length - 1;
      const branch = isLast ? icons.treeLast : icons.tree;
      const pipe = isLast ? '   ' : `${icons.pipe}  `;
      
      const slug = serverSlug(server);
      checkedServers++;
      
      // Registry lookup
      const registryData = await checkRegistry(slug);
      
      // Also try with server name directly
      let regData = registryData;
      if (!regData && slug !== server.name.toLowerCase()) {
        regData = await checkRegistry(server.name.toLowerCase());
      }
      
      // Determine source display
      let sourceLabel = '';
      if (server.npmPackage) sourceLabel = `${c.dim}npm:${server.npmPackage}${c.reset}`;
      else if (server.pyPackage) sourceLabel = `${c.dim}pip:${server.pyPackage}${c.reset}`;
      else if (server.url) sourceLabel = `${c.dim}${server.url.length > 60 ? server.url.slice(0, 57) + '...' : server.url}${c.reset}`;
      else if (server.command) sourceLabel = `${c.dim}${[server.command, ...server.args.slice(0, 2)].join(' ')}${c.reset}`;
      
      // Always resolve source URL (needed for --scan)
      const resolvedUrl = await resolveSourceUrl(server);
      
      if (regData) {
        auditedServers++;
        const riskScore = regData.risk_score ?? regData.latest_risk_score ?? 0;
        const hasOfficial = regData.has_official_audit;
        console.log(`${branch}  ${c.bold}${server.name}${c.reset}    ${sourceLabel}`);
        console.log(`${pipe}  ${riskBadge(riskScore)}  ${hasOfficial ? `${c.green}✔ official${c.reset}  ` : ''}${c.dim}${REGISTRY_URL}/packages/${slug}${c.reset}`);
        if (resolvedUrl || server.localDir || server.pyPackage || server.npmPackage) allServersWithUrls.push({ name: server.name, sourceUrl: resolvedUrl, localDir: server.localDir, pyPackage: server.pyPackage, npmPackage: server.npmPackage, hasAudit: true, regData });
      } else {
        unauditedServers++;
        console.log(`${branch}  ${c.bold}${server.name}${c.reset}    ${sourceLabel}`);
        if (resolvedUrl) {
          console.log(`${pipe}  ${c.yellow}⚠ not audited${c.reset}  ${c.dim}Run: ${c.cyan}agentaudit audit ${resolvedUrl}${c.reset}`);
          unauditedWithUrls.push({ name: server.name, sourceUrl: resolvedUrl });
          allServersWithUrls.push({ name: server.name, sourceUrl: resolvedUrl, localDir: server.localDir, pyPackage: server.pyPackage, npmPackage: server.npmPackage, hasAudit: false });
        } else if (server.localDir || server.pyPackage || server.npmPackage) {
          console.log(`${pipe}  ${c.yellow}⚠ not audited${c.reset}  ${c.dim}${server.localDir ? 'local install found' : 'package registry available'} — will scan${c.reset}`);
          allServersWithUrls.push({ name: server.name, sourceUrl: null, localDir: server.localDir, pyPackage: server.pyPackage, npmPackage: server.npmPackage, hasAudit: false });
        } else {
          console.log(`${pipe}  ${c.yellow}⚠ not audited${c.reset}  ${c.dim}Source URL unknown — check the package's GitHub/npm page${c.reset}`);
        }
      }
      
      if (server.sourceUrl && !server.sourceUrl.includes('npmjs.com')) {
        console.log(`${pipe}  ${c.dim}source: ${server.sourceUrl}${c.reset}`);
      }
    }
    
    console.log();
  }
  
  // Summary
  console.log(sectionHeader(`Summary — ${totalServers} server${totalServers !== 1 ? 's' : ''} across ${configs.length} config${configs.length !== 1 ? 's' : ''}`));
  console.log();
  if (auditedServers > 0) console.log(`  ${icons.safe}  ${c.green}${auditedServers} audited${c.reset}`);
  if (unauditedServers > 0) console.log(`  ${icons.caution}  ${c.yellow}${unauditedServers} not audited${c.reset}`);
  if (totalServers > 0) {
    console.log();
    console.log(`  ${coverageBar(auditedServers, totalServers)}`);
  }
  console.log();
  
  // ── Skill Discovery ──────────────────────────────────
  const skills = findSkills();
  if (skills.length > 0) {
    console.log(sectionHeader(`Skills — ${skills.length} found`));
    console.log();

    // Group by source
    const bySource = {};
    for (const skill of skills) {
      (bySource[skill.source] || (bySource[skill.source] = [])).push(skill);
    }

    for (const [source, sourceSkills] of Object.entries(bySource)) {
      console.log(`${icons.bullet}  ${c.bold}${source}${c.reset}`);
      console.log();

      for (let i = 0; i < sourceSkills.length; i++) {
        const skill = sourceSkills[i];
        const isLast = i === sourceSkills.length - 1;
        const branch = isLast ? icons.treeLast : icons.tree;
        const pipe = isLast ? '   ' : `${icons.pipe}  `;
        const { errors, warnings, info } = skill.validation;
        const name = info.name || skill.dirName;
        const hasErrors = errors.length > 0;
        const hasWarnings = warnings.length > 0;

        // Status indicator
        let status;
        if (hasErrors) status = `${c.red}✖ ${errors.length} error${errors.length !== 1 ? 's' : ''}${c.reset}`;
        else if (hasWarnings) status = `${c.yellow}⚠ ${warnings.length} warning${warnings.length !== 1 ? 's' : ''}${c.reset}`;
        else status = `${c.green}✔ valid${c.reset}`;

        console.log(`${branch}  ${c.bold}${name}${c.reset}    ${status}`);

        // Description (truncated)
        if (info.description) {
          const desc = info.description.length > 70 ? info.description.slice(0, 67) + '...' : info.description;
          console.log(`${pipe}  ${c.dim}${desc}${c.reset}`);
        }

        // MCP tool references
        if (info.mcpServers && info.mcpServers.length > 0) {
          const serverList = info.mcpServers.map(s => `${c.cyan}${s}${c.reset}`).join(', ');
          console.log(`${pipe}  ${c.dim}uses MCP:${c.reset} ${serverList}`);
        }

        // Allowed tools summary
        if (info.allowedTools === null) {
          console.log(`${pipe}  ${c.yellow}⚠ no allowed-tools — unrestricted access${c.reset}`);
        } else if (info.allowedTools && info.allowedTools.length > 0) {
          const toolCount = info.allowedTools.length;
          console.log(`${pipe}  ${c.dim}${toolCount} allowed tool${toolCount !== 1 ? 's' : ''}${c.reset}`);
        }

        // Show errors/warnings inline
        if (hasErrors) {
          for (const err of errors.slice(0, 3)) {
            console.log(`${pipe}  ${c.red}  ✖ ${err}${c.reset}`);
          }
        }
        if (hasWarnings && !hasErrors) {
          for (const warn of warnings.slice(0, 2)) {
            console.log(`${pipe}  ${c.yellow}  ⚠ ${warn}${c.reset}`);
          }
        }
      }
      console.log();
    }
  }

  // --scan: automatically scan all servers (git clone + local fallback)
  if (autoScan) {
    const isCloneable = (url) => /^https?:\/\/(github\.com|gitlab\.com|bitbucket\.org)\//i.test(url);
    // Include servers that are cloneable OR have a local dir OR a known package
    const scanTargets = allServersWithUrls.filter(s =>
      (s.sourceUrl && isCloneable(s.sourceUrl)) || s.localDir || s.pyPackage || s.npmPackage
    );
    // Deduplicate by sourceUrl or localDir
    const seen = new Set();
    const dedupedTargets = scanTargets.filter(s => {
      const key = (s.sourceUrl && isCloneable(s.sourceUrl)) ? s.sourceUrl : s.localDir;
      if (!key || seen.has(key)) return false;
      seen.add(key);
      return true;
    });
    const skippedCount = allServersWithUrls.length - scanTargets.length;
    if (dedupedTargets.length > 0) {
      console.log(sectionHeader(`Auto-scanning ${dedupedTargets.length} server${dedupedTargets.length !== 1 ? 's' : ''}`));
      console.log(`  ${c.bold}${icons.scan}  Starting scans...${c.reset}`);
      if (skippedCount > 0) {
        console.log(`  ${c.dim}(${skippedCount} skipped — remote-only, no local source)${c.reset}`);
      }
      console.log();

      const scanResults = [];
      for (const target of dedupedTargets) {
        let result = null;
        // Try git clone first if URL is cloneable
        if (target.sourceUrl && isCloneable(target.sourceUrl)) {
          result = await scanRepo(target.sourceUrl);
        }
        // Fallback 1: scan local installation
        if (!result && target.localDir) {
          result = await scanLocalDir(target.localDir, target.name);
        }
        // Fallback 2: download from PyPI/npm and scan
        if (!result && (target.pyPackage || target.npmPackage)) {
          result = await downloadAndScan(target);
        }
        if (result) scanResults.push({ ...result, serverName: target.name });
      }
      
      if (scanResults.length > 1) {
        // Print combined scan summary
        console.log(sectionHeader(`Scan Summary — ${scanResults.length} server${scanResults.length !== 1 ? 's' : ''} scanned`));
        console.log();
        
        let totalFindings = 0;
        let serversWithFindings = 0;
        
        for (const r of scanResults) {
          const findingCount = r.findings ? r.findings.length : 0;
          totalFindings += findingCount;
          if (findingCount > 0) serversWithFindings++;
          
          const status = findingCount === 0
            ? `${icons.safe}  ${c.green}clean${c.reset}`
            : `${icons.caution}  ${c.yellow}${findingCount} finding${findingCount !== 1 ? 's' : ''}${c.reset}`;
          console.log(`  ${status}  ${c.bold}${r.serverName || r.slug}${c.reset}  ${c.dim}(${r.duration})${c.reset}`);
        }
        
        console.log();
        if (serversWithFindings > 0) {
          console.log(`  ${c.yellow}${serversWithFindings}/${scanResults.length} server${scanResults.length !== 1 ? 's' : ''} with findings (${totalFindings} total)${c.reset}`);
          console.log(`  ${c.dim}Run ${c.cyan}agentaudit scan <url> --deep${c.dim} for deep LLM analysis on flagged servers${c.reset}`);
        } else {
          console.log(`  ${c.green}All servers passed quick scan${c.reset}`);
          console.log(`  ${c.dim}Run ${c.cyan}agentaudit scan <url> --deep${c.dim} for thorough LLM-powered analysis${c.reset}`);
        }
        console.log();
      }
    } else {
      console.log(`  ${c.dim}No scannable source URLs found.${c.reset}`);
      console.log();
    }
  } else if (interactiveAudit && allServersWithUrls.length > 0) {
    // Interactive multi-select for audit
    const isCloneable = (url) => /^https?:\/\/(github\.com|gitlab\.com|bitbucket\.org)\//i.test(url);
    const auditCandidates = [];
    const seen = new Set();
    for (const s of allServersWithUrls) {
      if (!s.sourceUrl || !isCloneable(s.sourceUrl)) continue;
      if (seen.has(s.sourceUrl)) continue;
      seen.add(s.sourceUrl);
      auditCandidates.push(s);
    }
    
    if (auditCandidates.length > 0) {
      console.log();
      const items = auditCandidates.map(s => ({
        label: s.name,
        sublabel: s.hasAudit ? `${c.green}✔ audited${c.reset}  ${s.sourceUrl}` : s.sourceUrl,
        value: s,
        checked: !s.hasAudit, // Pre-select unaudited
      }));
      
      const selected = await multiSelect(items, {
        title: 'Select servers to audit',
        hint: 'Space=toggle  ↑↓=move  a=all  n=none  Enter=confirm',
      });
      
      if (selected.length > 0) {
        console.log();
        console.log(`  ${c.bold}Auditing ${selected.length} server${selected.length !== 1 ? 's' : ''}...${c.reset}`);
        console.log();
        for (const s of selected) {
          await auditRepo(s.sourceUrl);
          console.log();
        }
      } else {
        console.log();
        console.log(`  ${c.dim}No servers selected.${c.reset}`);
      }
    }
  } else if (unauditedServers > 0) {
    if (unauditedWithUrls.length > 0) {
      console.log(`  ${c.dim}To audit unaudited servers:${c.reset}`);
      for (const { name, sourceUrl } of unauditedWithUrls) {
        console.log(`  ${c.cyan}agentaudit audit ${sourceUrl}${c.reset}  ${c.dim}(${name})${c.reset}`);
      }
    } else {
      console.log(`  ${c.dim}To audit unaudited servers, run:${c.reset}`);
      console.log(`  ${c.cyan}agentaudit audit <source-url>${c.reset}`);
    }
    console.log();
    console.log(`  ${c.dim}Or run ${c.cyan}agentaudit discover --quick${c.dim} to quick-scan all servers${c.reset}`);
    console.log(`  ${c.dim}Or run ${c.cyan}agentaudit discover --deep${c.dim} to select & deep-audit interactively${c.reset}`);
    console.log();
  }
  
  if (!autoScan && !interactiveAudit && !jsonMode) {
    console.log(`  ${c.dim}Run ${c.cyan}agentaudit discover --quick${c.dim} to auto-scan all servers${c.reset}`);
    console.log();
  }
}

// ── Audit command (deep LLM-powered) ────────────────────

function loadAuditPrompt() {
  const promptPath = path.join(SKILL_DIR, 'prompts', 'audit-prompt.md');
  if (fs.existsSync(promptPath)) return fs.readFileSync(promptPath, 'utf8');
  return null;
}

function loadVerificationPrompt() {
  const promptPath = path.join(SKILL_DIR, 'prompts', 'verification-prompt.md');
  if (fs.existsSync(promptPath)) return fs.readFileSync(promptPath, 'utf8');
  // Fallback: embedded minimal prompt
  return `You are a security verification auditor. Your job is to CHALLENGE a finding from a security scan.
Verify whether the cited code exists and the vulnerability is real. Respond with ONLY a JSON object:
{"verification_status":"verified|demoted|rejected","original_severity":"...","verified_severity":"...","verified_confidence":"high|medium|low","code_exists":true|false,"code_matches_description":true|false,"is_opt_in":true|false,"is_core_functionality":true|false,"attack_scenario":"...","rejection_reason":"...","reasoning":"..."}
Decision rules: code_exists=false→REJECTED; code_matches_description=false→REJECTED; is_opt_in=true AND severity critical/high→DEMOTED to low; no attack_scenario AND severity critical/high→DEMOTED to medium.`;
}

// Known context window sizes (input tokens) for common models
const MODEL_CONTEXT_LIMITS = {
  'claude-sonnet-4-6': 200000, 'claude-opus-4-6': 200000,
  'claude-sonnet-4': 200000, 'claude-opus-4': 200000, 'claude-haiku-4': 200000,
  'claude-3.5-sonnet': 200000, 'claude-3-haiku': 200000,
  'gpt-4.1': 1047576, 'gpt-4.1-mini': 1047576, 'gpt-4.1-nano': 1047576,
  'gpt-4o': 128000, 'gpt-4o-mini': 128000, 'gpt-4-turbo': 128000, 'gpt-4': 8192,
  'gemini-3.1-pro': 1048576, 'gemini-3.1-flash': 1048576,
  'gemini-2.5-flash': 1048576, 'gemini-2.5-pro': 1048576, 'gemini-2.0-flash': 1048576,
  'grok-4': 256000, 'grok-3': 131072,
  'deepseek-chat': 64000, 'deepseek-reasoner': 64000,
  'mistral-large': 128000, 'mistral-small': 32000,
};

function estimateTokens(text) { return Math.ceil(text.length / 3.5); }

// Sorted keys: longest first so "gpt-4.1" matches before "gpt-4", "claude-sonnet-4-6" before "claude-sonnet-4"
const MODEL_LIMIT_KEYS = Object.keys(MODEL_CONTEXT_LIMITS).sort((a, b) => b.length - a.length);

function checkContextLimit(model, systemPrompt, userMessage) {
  const stripped = model.replace(/^(anthropic|openai|google|openrouter|meta-llama|mistralai)\//i, '').toLowerCase();
  const modelKey = MODEL_LIMIT_KEYS.find(k => stripped.includes(k.toLowerCase()));
  if (!modelKey) return null; // unknown model, skip check
  const limit = MODEL_CONTEXT_LIMITS[modelKey];
  const estimated = estimateTokens(systemPrompt) + estimateTokens(userMessage);
  if (estimated > limit * 0.9) {
    return { estimated, limit, pct: Math.round(estimated / limit * 100) };
  }
  return null;
}

/**
 * Safely parse JSON from a fetch response. If the response is not JSON
 * (e.g. HTML error page from a 502/503), returns {error: {message: ...}}
 * which the callLlm error handling paths already handle.
 */
async function safeJsonParse(res, llmConfig) {
  const contentType = res.headers.get('content-type') || '';
  // Read body as text first — we can only consume the stream once
  let body;
  try { body = await res.text(); } catch { body = ''; }

  if (!res.ok && !contentType.includes('application/json')) {
    // Non-JSON error response (e.g. HTML from a proxy/gateway)
    const preview = body.slice(0, 200).replace(/<[^>]+>/g, '').trim();
    return { error: { message: `HTTP ${res.status} from ${llmConfig.provider}${preview ? ': ' + preview : ''}` } };
  }
  try {
    return JSON.parse(body);
  } catch (parseErr) {
    const preview = body.slice(0, 200).replace(/<[^>]+>/g, '').trim();
    return { error: { message: `Invalid JSON from ${llmConfig.provider} (HTTP ${res.status}): ${preview || parseErr.message}` } };
  }
}

function getMaxOutputTokens(model) {
  // Known max_completion_tokens from provider docs / OpenRouter API
  const limits = {
    // Anthropic
    'claude-haiku-4-5': 8192, 'claude-3-haiku': 4096, 'claude-3-5-haiku': 8192,
    'claude-sonnet-4-6': 64000, 'claude-sonnet-4-5': 16384, 'claude-3-5-sonnet': 8192,
    'claude-opus-4-6': 32768, 'claude-opus-4': 32768,
    // Google Gemini (all current models support 65536)
    'gemini-3': 65536, 'gemini-2.5': 65536, 'gemini-2.0': 65536,
    // Qwen
    'qwen3.5': 65536, 'qwen3': 32768, 'qwen2.5': 32768,
    // xAI
    'grok-4': 32768, 'grok-3': 16384,
    // OpenAI
    'gpt-4.1': 32768, 'gpt-4o': 16384, 'gpt-4-turbo': 4096,
    'o3': 100000, 'o4-mini': 100000,
  };
  const m = (model || '').toLowerCase();
  for (const [key, val] of Object.entries(limits)) {
    if (m.includes(key)) return val;
  }
  return 16384; // conservative fallback for unknown models
}

async function callLlm(llmConfig, systemPrompt, userMessage) {
  const apiKey = process.env[llmConfig.key];
  if (!apiKey) return { error: `Missing API key: ${llmConfig.key}` };
  const start = Date.now();

  // Context window warning
  const ctxCheck = checkContextLimit(llmConfig.model, systemPrompt, userMessage);
  if (ctxCheck) {
    console.log(`  ${c.yellow}⚠ Input ~${Math.round(ctxCheck.estimated/1000)}k tokens (${ctxCheck.pct}% of ${Math.round(ctxCheck.limit/1000)}k context window)${c.reset}`);
    if (ctxCheck.pct > 100) {
      return { error: `Input too large (~${Math.round(ctxCheck.estimated/1000)}k tokens) for ${llmConfig.model} (${Math.round(ctxCheck.limit/1000)}k context limit). Try a smaller package or a model with a larger context window.` };
    }
  }

  let _text = '';
  try {
    let data;
    if (llmConfig.type === 'anthropic') {
      const res = await fetch(llmConfig.url, {
        method: 'POST',
        headers: { 'x-api-key': apiKey, 'anthropic-version': '2023-06-01', 'content-type': 'application/json' },
        body: JSON.stringify({ model: llmConfig.model, max_tokens: getMaxOutputTokens(llmConfig.model), system: systemPrompt, messages: [{ role: 'user', content: userMessage }] }),
        signal: AbortSignal.timeout(180_000),
      });
      data = await safeJsonParse(res, llmConfig);
      if (data.error) {
        const friendly = formatApiError(data.error, llmConfig.provider, res.status);
        return { error: friendly?.text || data.error.message || JSON.stringify(data.error), hint: friendly?.hint, duration: Date.now() - start };
      }
      _text = data.content?.[0]?.text || '';
      if (data.stop_reason === 'max_tokens') {
        console.log(`  ${c.red}✗ Output truncated — model hit max_tokens limit (${data.usage?.output_tokens || '?'} tokens). Results may be incomplete.${c.reset}`);
        console.log(`  ${c.dim}  Hint: Try a model with higher output capacity, or scan a smaller package.${c.reset}`);
      }
      const report = extractJSON(_text);
      if (report) {
        report.audit_model = data.model || llmConfig.model;
        report.audit_provider = llmConfig.provider;
        if (data.id) report.provider_msg_id = data.id;
        if (data.usage) { report.input_tokens = data.usage.input_tokens; report.output_tokens = data.usage.output_tokens; }
        if (data.stop_reason === 'max_tokens') report.output_truncated = true;
      }
      return { report, text: _text, duration: Date.now() - start, truncated: data.stop_reason === 'max_tokens' };
    } else if (llmConfig.type === 'gemini') {
      // NOTE: Google's Gemini API requires the API key as a URL query parameter.
      // This is by design (their auth model). We never log the full URL to avoid key leakage.
      const geminiUrl = `${llmConfig.url}/${llmConfig.model}:generateContent?key=${apiKey}`;
      const res = await fetch(geminiUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          systemInstruction: { parts: [{ text: systemPrompt }] },
          contents: [{ role: 'user', parts: [{ text: userMessage }] }],
          generationConfig: { maxOutputTokens: getMaxOutputTokens(llmConfig.model), responseMimeType: 'application/json', thinkingConfig: { thinkingBudget: 8192 } },
        }),
        signal: AbortSignal.timeout(180_000),
      });
      data = await safeJsonParse(res, llmConfig);
      if (data.error) {
        const friendly = formatApiError(data.error, llmConfig.provider, res.status);
        return { error: friendly?.text || data.error.message || JSON.stringify(data.error), hint: friendly?.hint, duration: Date.now() - start };
      }
      _text = data.candidates?.[0]?.content?.parts?.[0]?.text || '';
      const geminiFinish = data.candidates?.[0]?.finishReason;
      if (geminiFinish === 'MAX_TOKENS') {
        console.log(`  ${c.red}✗ Output truncated — model hit maxOutputTokens limit (${data.usageMetadata?.candidatesTokenCount || '?'} tokens). Results may be incomplete.${c.reset}`);
        console.log(`  ${c.dim}  Hint: Try a model with higher output capacity, or scan a smaller package.${c.reset}`);
      }
      const report = extractJSON(_text);
      if (report) {
        report.audit_model = data.modelVersion || llmConfig.model;
        report.audit_provider = llmConfig.provider;
        if (data.usageMetadata) { report.input_tokens = data.usageMetadata.promptTokenCount; report.output_tokens = data.usageMetadata.candidatesTokenCount; }
        if (geminiFinish === 'MAX_TOKENS') report.output_truncated = true;
      }
      return { report, text: _text, duration: Date.now() - start, truncated: geminiFinish === 'MAX_TOKENS' };
    } else {
      const headers = { 'Authorization': `Bearer ${apiKey}`, 'Content-Type': 'application/json' };
      if (llmConfig.provider === 'openrouter') { headers['HTTP-Referer'] = 'https://agentaudit.dev'; headers['X-Title'] = 'AgentAudit CLI'; }
      const res = await fetch(llmConfig.url, {
        method: 'POST',
        headers,
        body: JSON.stringify({ model: llmConfig.model, max_tokens: getMaxOutputTokens(llmConfig.model), messages: [{ role: 'system', content: systemPrompt }, { role: 'user', content: userMessage }] }),
        signal: AbortSignal.timeout(180_000),
      });
      data = await safeJsonParse(res, llmConfig);
      if (data.error) {
        const friendly = formatApiError(data.error, llmConfig.provider, res.status);
        return { error: friendly?.text || data.error.message || JSON.stringify(data.error), hint: friendly?.hint, duration: Date.now() - start };
      }
      _text = data.choices?.[0]?.message?.content || '';
      const oaiFinish = data.choices?.[0]?.finish_reason;
      if (oaiFinish === 'length') {
        console.log(`  ${c.red}✗ Output truncated — model hit max_tokens limit (${data.usage?.completion_tokens || '?'} tokens). Results may be incomplete.${c.reset}`);
        console.log(`  ${c.dim}  Hint: Try a model with higher output capacity, or scan a smaller package.${c.reset}`);
      }
      const report = extractJSON(_text);
      if (report) {
        report.audit_model = data.model || llmConfig.model;
        report.audit_provider = llmConfig.provider;
        if (data.id) report.provider_msg_id = data.id;
        if (data.system_fingerprint) report.provider_fingerprint = data.system_fingerprint;
        if (data.usage) { report.input_tokens = data.usage.prompt_tokens; report.output_tokens = data.usage.completion_tokens; }
        if (oaiFinish === 'length') report.output_truncated = true;
      }
      return { report, text: _text, duration: Date.now() - start, truncated: oaiFinish === 'length' };
    }
  } catch (err) {
    const dur = Date.now() - start;
    if (err.name === 'TimeoutError' || err.message?.includes('timeout')) return { error: 'Request timed out (180s)', hint: 'Try again or use a faster model', duration: dur };
    if (err.code === 'ENOTFOUND' || err.code === 'ECONNREFUSED' || err.message?.includes('fetch failed')) return { error: `Network error: could not reach ${llmConfig.provider}`, hint: 'Check your internet connection', duration: dur };
    return { error: err.message, duration: dur };
  }
}

// ── Deterministic post-processing for LLM reports ────────────────────────
// Fills in missing fields that LLMs often omit, using deterministic lookups

const PATTERN_CWE_MAP = {
  CMD_INJECT: 'CWE-78', CRED_THEFT: 'CWE-522', DATA_EXFIL: 'CWE-200',
  DESTRUCT: 'CWE-912', OBF: 'CWE-506', SANDBOX_ESC: 'CWE-693',
  SUPPLY_CHAIN: 'CWE-1357', SOCIAL_ENG: 'CWE-451', PRIV_ESC: 'CWE-269',
  INFO_LEAK: 'CWE-200', CRYPTO_WEAK: 'CWE-327', DESER: 'CWE-502',
  PATH_TRAV: 'CWE-22', SEC_BYPASS: 'CWE-693', PERSIST: 'CWE-912',
  AI_PROMPT: 'CWE-1426', MCP_POISON: 'CWE-1426', MCP_INJECT: 'CWE-94',
  MCP_TRAVERSAL: 'CWE-22', MCP_SUPPLY: 'CWE-1357', MCP_PERM: 'CWE-269',
  WORM: 'CWE-912', CICD: 'CWE-912', CORR: 'CWE-829', MANUAL: 'CWE-693',
};

const SEVERITY_IMPACT = { critical: -25, high: -15, medium: -5, low: -1 };

const REMEDIATION_TEMPLATES = {
  CMD_INJECT: 'Validate and sanitize input; use allowlists or parameterized execution instead of shell strings',
  CRED_THEFT: 'Remove hardcoded credentials; use environment variables or a secrets manager',
  DATA_EXFIL: 'Remove or document the external data transmission; ensure user consent',
  DESTRUCT: 'Add confirmation prompts and safeguards before destructive operations',
  OBF: 'Replace obfuscated code with readable equivalents; document the purpose',
  SANDBOX_ESC: 'Restrict file and process access to configured boundaries',
  SUPPLY_CHAIN: 'Pin dependency versions; verify package integrity',
  SOCIAL_ENG: 'Align documentation with actual code behavior',
  PRIV_ESC: 'Apply principle of least privilege; remove unnecessary elevated permissions',
  INFO_LEAK: 'Restrict exposed information to what is necessary for operation',
  CRYPTO_WEAK: 'Use modern cryptographic algorithms (AES-256, SHA-256+)',
  DESER: 'Use safe deserialization (e.g. yaml.safe_load, JSON) instead of unsafe loaders',
  PATH_TRAV: 'Sanitize file paths; reject inputs containing .. or absolute paths',
  SEC_BYPASS: 'Do not disable security controls; use proper certificate validation',
  PERSIST: 'Remove persistence mechanisms or require explicit user opt-in',
  AI_PROMPT: 'Remove hidden instructions; ensure tool descriptions are transparent',
  MCP_POISON: 'Remove injected instructions from tool descriptions and schemas',
  MCP_INJECT: 'Sanitize tool arguments and descriptions; prevent prompt injection',
  MCP_TRAVERSAL: 'Validate and sandbox file paths in MCP tool handlers',
  MCP_SUPPLY: 'Pin MCP package versions; verify transport configurations',
  MCP_PERM: 'Restrict permissions to minimum required scope; remove wildcard grants',
};

function enrichFindings(report, files, pkgInfo) {
  if (!report || !report.findings) return report;

  // Ensure package_version
  if (!report.package_version || report.package_version === 'unknown') {
    report.package_version = pkgInfo.version || 'unknown';
  }

  // Ensure max_severity
  const severities = ['critical', 'high', 'medium', 'low'];
  let maxSev = 'none';
  for (const f of report.findings) {
    const idx = severities.indexOf((f.severity || '').toLowerCase());
    if (idx !== -1 && idx < severities.indexOf(maxSev === 'none' ? 'low' : maxSev)) {
      maxSev = severities[idx];
    }
  }
  // Only override if not set or wrong
  if (!report.max_severity || report.max_severity === 'none') {
    report.max_severity = report.findings.length > 0 ? maxSev : 'none';
  }

  const VALID_SEVERITIES = new Set(['critical', 'high', 'medium', 'low', 'info']);

  for (const finding of report.findings) {
    // 0. Validate & sanitize finding fields
    // Severity: must be one of the known values
    const sev = (finding.severity || '').toLowerCase();
    finding.severity = VALID_SEVERITIES.has(sev) ? sev : 'medium';
    // Line number: must be a positive integer
    if (finding.line != null) {
      const lineNum = parseInt(finding.line, 10);
      finding.line = (Number.isFinite(lineNum) && lineNum > 0) ? lineNum : undefined;
    }
    // File path: reject suspicious characters (null bytes, .., protocol schemes)
    if (finding.file && (/[\x00]|\.\.[\\/]|^[a-z]+:\/\//i.test(finding.file))) {
      finding.file = undefined;
    }

    // 1. Fill cwe_id from pattern_id lookup
    if (!finding.cwe_id || finding.cwe_id === '') {
      const prefix = (finding.pattern_id || '').replace(/_\d+$/, '');
      finding.cwe_id = PATTERN_CWE_MAP[prefix] || 'CWE-693';
    }

    // 2. Fill content (code snippet) from files array
    if ((!finding.content || finding.content === '' || finding.content === '...') && finding.file && finding.line) {
      const matchFile = files.find(f => f.path === finding.file || f.path.endsWith('/' + finding.file));
      if (matchFile) {
        const lines = matchFile.content.split('\n');
        const lineIdx = finding.line - 1;
        if (lineIdx >= 0 && lineIdx < lines.length) {
          // Extract 1-3 lines around the target
          const start = Math.max(0, lineIdx - 1);
          const end = Math.min(lines.length, lineIdx + 2);
          finding.content = lines.slice(start, end).map(l => l.trimEnd()).join('\n').trim();
        }
      }
    }

    // 3. Fill remediation from template
    if (!finding.remediation || finding.remediation === '' || finding.remediation === '...') {
      const prefix = (finding.pattern_id || '').replace(/_\d+$/, '');
      finding.remediation = REMEDIATION_TEMPLATES[prefix] || 'Review and address the identified security concern';
    }

    // 4. Ensure score_impact is set correctly
    if (finding.score_impact === undefined || finding.score_impact === null) {
      if (finding.by_design) {
        finding.score_impact = 0;
      } else {
        finding.score_impact = SEVERITY_IMPACT[(finding.severity || '').toLowerCase()] || -5;
      }
    }

    // 5. Ensure confidence has valid value
    if (!['high', 'medium', 'low'].includes(finding.confidence)) {
      finding.confidence = 'medium';
    }

    // 6. Ensure by_design is boolean
    if (typeof finding.by_design !== 'boolean') {
      finding.by_design = false;
    }
  }

  // Recalculate risk_score from findings
  const computedRisk = report.findings.reduce((sum, f) => {
    if (f.by_design) return sum;
    return sum + Math.abs(f.score_impact || 0);
  }, 0);
  report.risk_score = Math.min(100, computedRisk);

  // Ensure result matches risk_score
  if (report.risk_score <= 25) report.result = 'safe';
  else if (report.risk_score <= 50) report.result = 'caution';
  else report.result = 'unsafe';

  // Ensure findings_count
  report.findings_count = report.findings.length;

  return report;
}

// ── SARIF 2.1.0 output ────────────────────────────────

function toSarif(reports) {
  if (!reports || (Array.isArray(reports) && reports.length === 0)) {
    reports = [];
  }
  const version = getVersion();
  const LEVEL_MAP = { critical: 'error', high: 'error', medium: 'warning', low: 'note', info: 'note' };
  const SCORE_MAP = { critical: '9.5', high: '8.0', medium: '5.5', low: '2.0', info: '0.5' };
  const rules = [];
  const results = [];
  const ruleIndex = new Map();

  for (const report of (Array.isArray(reports) ? reports : [reports]).filter(Boolean)) {
    for (const f of (report.findings || [])) {
      const ruleId = f.pattern_id || f.id || 'UNKNOWN';
      const sev = (f.severity || 'medium').toLowerCase();

      if (!ruleIndex.has(ruleId)) {
        ruleIndex.set(ruleId, rules.length);
        const tags = ['security'];
        if (f.cwe_id) tags.push(f.cwe_id.toLowerCase());
        if (f.category) tags.push(f.category);
        rules.push({
          id: ruleId,
          shortDescription: { text: f.title || ruleId },
          fullDescription: { text: f.description || f.title || '' },
          helpUri: f.cwe_id
            ? `https://cwe.mitre.org/data/definitions/${f.cwe_id.replace('CWE-', '')}.html`
            : `https://agentaudit.dev`,
          defaultConfiguration: { level: LEVEL_MAP[sev] || 'warning' },
          properties: { 'security-severity': SCORE_MAP[sev] || '5.5', tags },
        });
      }

      const result = {
        ruleId,
        ruleIndex: ruleIndex.get(ruleId),
        level: LEVEL_MAP[sev] || 'warning',
        message: { text: [f.title, f.description].filter(Boolean).join(': ') },
        locations: [],
      };

      const filePath = f.file || f.file_path;
      const lineNum = f.line || f.line_start;
      if (filePath) {
        const loc = {
          physicalLocation: {
            artifactLocation: { uri: filePath, uriBaseId: '%SRCROOT%' },
          },
        };
        if (lineNum) {
          loc.physicalLocation.region = { startLine: lineNum };
        }
        const snippet = f.content || f.snippet || f.code_snippet;
        if (snippet) {
          loc.physicalLocation.region = loc.physicalLocation.region || {};
          loc.physicalLocation.region.snippet = { text: snippet };
        }
        result.locations.push(loc);
      }

      if (f.remediation) {
        result.fixes = [{ description: { text: f.remediation } }];
      }

      if (f.by_design) {
        result.suppressions = [{ kind: 'inSource', justification: 'Marked as by-design' }];
      }

      if (filePath && lineNum) {
        const hash = crypto.createHash('sha256')
          .update(`${ruleId}:${filePath}:${lineNum}`)
          .digest('hex').slice(0, 16);
        result.partialFingerprints = { primaryLocationLineHash: hash };
      } else {
        // Fallback fingerprint from rule + title for findings without file/line
        const hash = crypto.createHash('sha256')
          .update(`${ruleId}:${f.title || ''}`)
          .digest('hex').slice(0, 16);
        result.partialFingerprints = { primaryLocationLineHash: hash };
      }

      results.push(result);
    }
  }

  return {
    version: '2.1.0',
    $schema: 'https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json',
    runs: [{
      tool: {
        driver: {
          name: 'AgentAudit',
          semanticVersion: version,
          informationUri: 'https://agentaudit.dev',
          rules,
        },
      },
      results,
    }],
  };
}

// ── Verification Pass (Pass 2) ──────────────────────────
// Adversarial verification: re-examines each finding against actual source code

function buildVerificationMessage(finding, context) {
  return [
    `## Finding to Verify`,
    ``,
    `**Title:** ${finding.title}`,
    `**Severity:** ${finding.severity}`,
    `**Confidence:** ${finding.confidence || 'medium'}`,
    `**Pattern:** ${finding.pattern_id || 'unknown'} (${finding.cwe_id || 'N/A'})`,
    `**File:** ${finding.file || 'unknown'}${finding.line ? ':' + finding.line : ''}`,
    `**Description:** ${finding.description || ''}`,
    `**Cited Code:**`,
    '```',
    finding.content || '(no code cited)',
    '```',
    ``,
    `## Actual Source Code of ${finding.file || 'unknown'}`,
    ``,
    '```',
    context.sourceFileContent,
    '```',
    ``,
    `## Package File Listing (for context)`,
    ``,
    context.fileList,
    ``,
    `## Package Manifest`,
    ``,
    '```',
    context.manifestContent,
    '```',
    ``,
    `---`,
    `Verify this finding. Does the cited code exist? Is the vulnerability real?`,
    `Respond with ONLY the JSON verdict.`,
  ].join('\n');
}

function downgradeSeverity(severity) {
  const map = { critical: 'high', high: 'medium', medium: 'low', low: 'low', info: 'info' };
  return map[(severity || '').toLowerCase()] || severity;
}

async function verifyFindings(findings, files, verifierConfig, options = {}) {
  const { maxFindings = 10 } = options;

  if (!findings || findings.length === 0) return { finalFindings: [], stats: { total: 0, verified: 0, demoted: 0, rejected: 0, unverified: 0, inputTokens: 0, outputTokens: 0 } };

  const verificationPrompt = loadVerificationPrompt();
  if (!verificationPrompt) return { finalFindings: findings, stats: { total: findings.length, verified: 0, demoted: 0, rejected: 0, unverified: findings.length, inputTokens: 0, outputTokens: 0 } };

  // Sort by severity (critical first) and take top N
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const toVerify = [...findings]
    .sort((a, b) => (severityOrder[a.severity] ?? 4) - (severityOrder[b.severity] ?? 4))
    .slice(0, maxFindings);

  const fileList = files.map(f => `${f.path} (${(f.content || '').length} bytes)`).join('\n');
  const manifest = files.find(f =>
    f.path === 'package.json' || f.path === 'pyproject.toml' ||
    f.path === 'setup.py' || f.path === 'Cargo.toml'
  );

  const verified = [];
  const demoted = [];
  const rejected = [];

  let totalInputTokens = 0;
  let totalOutputTokens = 0;

  for (const finding of toVerify) {
    // Find the actual source file
    const sourceFile = files.find(f =>
      f.path === finding.file || f.path.endsWith('/' + finding.file)
    );

    const userMsg = buildVerificationMessage(finding, {
      sourceFileContent: sourceFile?.content || '(FILE NOT FOUND IN PACKAGE — this may indicate a fabricated file reference)',
      fileList,
      manifestContent: manifest?.content || '(no manifest found)',
    });

    try {
      const result = await callLlm(verifierConfig, verificationPrompt, userMsg);

      if (result.error) {
        finding.verification_status = 'unverified';
        finding.verification_reasoning = `Verification error: ${result.error}`;
        continue;
      }

      const verdict = extractJSON(result.text);
      totalInputTokens += result.inputTokens || 0;
      totalOutputTokens += result.outputTokens || 0;

      if (!verdict || !verdict.verification_status) {
        finding.verification_status = 'unverified';
        finding.verification_reasoning = 'Verification returned unparseable response';
        continue;
      }

      // Apply verdict
      finding.verification_model = verifierConfig.model;

      switch (verdict.verification_status) {
        case 'rejected':
          finding.verification_status = 'rejected';
          finding.verification_reasoning = verdict.rejection_reason || verdict.reasoning || 'Rejected by verification';
          finding.code_exists = verdict.code_exists;
          rejected.push(finding);
          break;

        case 'demoted':
          finding.verification_status = 'demoted';
          finding.original_severity = finding.severity;
          finding.severity = verdict.verified_severity || downgradeSeverity(finding.severity);
          finding.verified_confidence = verdict.verified_confidence || 'low';
          finding.verification_reasoning = verdict.reasoning || '';
          finding.is_opt_in = verdict.is_opt_in;
          finding.code_exists = verdict.code_exists;
          finding.by_design = verdict.is_opt_in || verdict.is_core_functionality || finding.by_design;
          finding.score_impact = finding.by_design ? 0 : (SEVERITY_IMPACT[finding.severity] || -5);
          demoted.push(finding);
          break;

        case 'verified':
        default:
          finding.verification_status = 'verified';
          finding.verified_confidence = verdict.verified_confidence || finding.confidence;
          finding.verification_reasoning = verdict.reasoning || '';
          finding.code_exists = verdict.code_exists ?? true;
          // Adjust severity if verifier disagrees
          if (verdict.verified_severity && verdict.verified_severity !== finding.severity) {
            finding.original_severity = finding.severity;
            finding.severity = verdict.verified_severity;
            finding.score_impact = finding.by_design ? 0 : (SEVERITY_IMPACT[finding.severity] || -5);
          }
          verified.push(finding);
          break;
      }
    } catch (err) {
      finding.verification_status = 'unverified';
      finding.verification_reasoning = `Verification error: ${err.message || err}`;
    }
  }

  // Findings not sent to verification remain as-is
  const unverified = findings.filter(f => !toVerify.includes(f));
  for (const f of unverified) {
    if (!f.verification_status) f.verification_status = 'unverified';
  }

  // Final findings = verified + demoted + unverified (rejected are REMOVED)
  const finalFindings = [...verified, ...demoted, ...unverified];

  return {
    verified,
    demoted,
    rejected,
    unverified,
    finalFindings,
    stats: {
      total: findings.length,
      verified: verified.length,
      demoted: demoted.length,
      rejected: rejected.length,
      unverified: unverified.length,
      inputTokens: totalInputTokens,
      outputTokens: totalOutputTokens,
    },
  };
}

async function auditRepo(url) {
  // In quiet mode (SARIF/JSON), redirect all progress output to stderr
  // so stdout only contains clean machine-readable data
  const _origConsoleLog = console.log;
  const _origStdoutWrite = process.stdout.write;
  if (quietMode) {
    console.log = console.error;
    process.stdout.write = process.stderr.write.bind(process.stderr);
  }
  try {
  const start = Date.now();

  // Support local directories
  const isLocal = fs.existsSync(url) && fs.statSync(url).isDirectory();
  const slug = isLocal ? path.basename(url) : slugFromUrl(url);

  console.log(`${icons.scan}  ${c.bold}Auditing ${slug}${c.reset}  ${c.dim}${url}${c.reset}`);
  console.log(`${icons.pipe}  ${c.dim}Deep LLM-powered analysis (3-pass: UNDERSTAND → DETECT → CLASSIFY)${c.reset}`);
  console.log();

  let repoPath, tmpDir = null;

  if (isLocal) {
    // Local directory — no cloning needed
    repoPath = path.resolve(url);
    process.stdout.write(`  ${stepProgress(1, 4)} Reading local directory...`);
    console.log(` ${c.green}done${c.reset}`);
  } else {
    // Step 1: Clone
    process.stdout.write(`  ${stepProgress(1, 4)} Cloning repository...`);
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'agentaudit-'));
    repoPath = path.join(tmpDir, 'repo');
    try {
      safeGitClone(url, repoPath);
      console.log(` ${c.green}done${c.reset}`);
    } catch (err) {
      console.log(` ${c.red}failed${c.reset}`);
      const msg = err.stderr?.toString().trim() || err.message?.split('\n')[0] || '';
      if (msg) console.log(`    ${c.dim}${msg}${c.reset}`);
      console.log(`    ${c.dim}Make sure git is installed and the URL is accessible.${c.reset}`);
      return null;
    }
  }

  // Step 2: Collect files
  process.stdout.write(`  ${stepProgress(2, 4)} Collecting source files...`);
  const files = collectFiles(repoPath);
  console.log(` ${c.green}${files.length} files${c.reset}`);
  
  // Step 3: Build audit payload
  process.stdout.write(`  ${stepProgress(3, 4)} Preparing audit payload...`);
  const auditPrompt = loadAuditPrompt();
  
  let codeBlock = '';
  for (const file of files) {
    codeBlock += `\n### FILE: ${file.path}\n\`\`\`\n${file.content}\n\`\`\`\n`;
  }
  console.log(` ${c.green}done${c.reset}`);
  
  // Step 4: Provenance + type detection (needs repoPath on disk)
  let commitSha = '';
  try { commitSha = execSync('git rev-parse HEAD', { cwd: repoPath, encoding: 'utf8' }).trim(); } catch {}
  const sourceHash = crypto.createHash('sha256').update(
    files.slice().sort((a, b) => a.path.localeCompare(b.path))
      .map(f => f.path + '\n' + f.content).join('\n')
  ).digest('hex');
  const pkgInfo = detectPackageInfo(repoPath, files);
  const KNOWN_MCP_LIBS = new Set(['fastmcp', 'jlowin-fastmcp', 'mcp-go', 'fastapi-mcp', 'fastapi_mcp', 'mcp-use', 'mcp-agent']);
  const KNOWN_CLI = new Set(['mcp-cli', 'mcp-scan', 'inspector']);
  let detectedType = pkgInfo.type === 'unknown' ? 'other' : pkgInfo.type;
  if (KNOWN_MCP_LIBS.has(slug)) detectedType = 'library';
  if (KNOWN_CLI.has(slug)) detectedType = 'cli-tool';

  // Cleanup cloned repo (files in memory, provenance captured); skip for local dirs
  if (tmpDir) { try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {} }

  // Build prompts
  const systemPrompt = auditPrompt || 'You are a security auditor. Analyze the code and report findings as JSON.';
  const detectedVersion = pkgInfo.version || 'unknown';
  const userMessage = [
    `Audit this package: **${slug}** (${url})`,
    `Package version detected: ${detectedVersion}`,
    ``,
    `Respond with ONLY a valid JSON object. No markdown fences, no explanation, no text before or after.`,
    ``,
    `Required top-level fields: skill_slug, source_url, package_type, package_version, risk_score, max_severity, result, findings_count, findings`,
    `Required finding fields (ALL mandatory): pattern_id, cwe_id, severity, title, description, file, line, content, remediation, confidence, by_design, score_impact`,
    ``,
    `A finding missing cwe_id, content, or remediation is INVALID — do not emit it.`,
    ``,
    `## Source Code`,
    codeBlock,
  ].join('\n');

  // Helper: add provenance to a report
  const enrichReport = (report, duration) => {
    report.skill_slug = slug;
    report.package_type = detectedType;
    report.audit_duration_ms = duration || (Date.now() - start);
    report.files_scanned = files.length;
    if (commitSha) report.commit_sha = commitSha;
    report.source_hash = sourceHash;
  };

  // Helper: upload one report
  const uploadReport = async (report, creds) => {
    if (!creds) return;
    process.stdout.write(`  Uploading report${report.audit_model ? ` (${report.audit_model})` : ''}...`);
    try {
      const res = await fetch(`${REGISTRY_URL}/api/reports`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${creds.api_key}`, 'Content-Type': 'application/json' },
        body: JSON.stringify(report),
        signal: AbortSignal.timeout(15_000),
      });
      if (res.ok) {
        console.log(` ${c.green}done${c.reset}`);
      } else {
        let errBody = ''; try { errBody = await res.text(); } catch {}
        console.log(` ${c.yellow}failed (HTTP ${res.status})${c.reset}`);
        if (errBody && process.argv.includes('--debug')) console.log(`  ${c.dim}Server: ${errBody.slice(0, 300)}${c.reset}`);
      }
    } catch { console.log(` ${c.yellow}failed${c.reset}`); }
  };

  // Step 5: Resolve models
  const modelsArgIdx = process.argv.indexOf('--models');
  const modelsFlag = modelsArgIdx !== -1 ? process.argv[modelsArgIdx + 1] : null;
  const modelNames = modelsFlag ? modelsFlag.split(',').map(m => m.trim()).filter(Boolean) : [];
  const isMultiModel = modelNames.length > 1;

  // ── Multi-Model Path ─────────────────────────────────────
  if (isMultiModel) {
    const resolvedModels = [];
    const failedModels = [];
    for (const name of modelNames) {
      const config = resolveModel(name);
      if (!config) { failedModels.push(name); continue; }
      resolvedModels.push({ name, config });
    }

    if (resolvedModels.length === 0) {
      console.log();
      console.log(`  ${c.red}No API keys available for requested models${c.reset}`);
      for (const name of failedModels) console.log(`    ${c.dim}${name}: no matching API key${c.reset}`);
      console.log(`  ${c.dim}Run "agentaudit model" to configure providers${c.reset}`);
      return null;
    }

    // Progress
    const totalSteps = resolvedModels.length;
    console.log(`  ${stepProgress(4, 4)} Running LLM analysis ${c.dim}(${totalSteps} models in parallel)${c.reset}`);
    if (failedModels.length > 0) {
      for (const name of failedModels) console.log(`    ${c.yellow}⚠${c.reset} ${name.padEnd(30)} ${c.dim}skipped (no API key)${c.reset}`);
    }

    // Parallel LLM calls
    const results = await Promise.allSettled(
      resolvedModels.map(async ({ name, config }) => {
        const result = await callLlm(config, systemPrompt, userMessage);
        return { name, ...result };
      })
    );

    // Process results
    const reports = [];
    for (let i = 0; i < results.length; i++) {
      const name = resolvedModels[i].name;
      const r = results[i];
      if (r.status === 'rejected') {
        console.log(`    ${c.red}✗${c.reset} ${name.padEnd(30)} ${c.red}error${c.reset}`);
        continue;
      }
      const { report, text, error, hint, duration } = r.value;
      if (error) {
        console.log(`    ${c.red}✗${c.reset} ${name.padEnd(30)} ${c.red}${error}${c.reset}`);
        if (hint) console.log(`      ${c.dim}${hint}${c.reset}`);
        continue;
      }
      if (!report) {
        console.log(`    ${c.yellow}✗${c.reset} ${name.padEnd(30)} ${c.yellow}JSON parse failed${c.reset}`);
        if (process.argv.includes('--debug') && text) {
          console.log(`      ${c.dim}${text.slice(0, 200)}...${c.reset}`);
        }
        continue;
      }
      const durSec = Math.round((duration || 0) / 1000);
      console.log(`    ${c.green}✓${c.reset} ${name.padEnd(30)} ${c.green}done${c.reset} ${c.dim}(${durSec}s)${c.reset}`);
      enrichReport(report, duration);
      enrichFindings(report, files, pkgInfo);
      saveHistory(report);
      reports.push({ name, report });
    }

    if (reports.length === 0) {
      console.log();
      console.log(`  ${c.red}No models returned valid results${c.reset}`);
      return null;
    }

    // Display per-model results
    console.log();
    for (const { name, report } of reports) {
      console.log(sectionHeader(name));
      console.log(`  ${riskBadge(report.risk_score || 0)}`);
      const fc = report.findings?.length || 0;
      if (fc > 0) {
        const counts = {};
        for (const f of report.findings) { const s = (f.severity || 'info').toLowerCase(); counts[s] = (counts[s] || 0) + 1; }
        const parts = [];
        for (const sev of ['critical', 'high', 'medium', 'low', 'info']) { if (counts[sev]) parts.push(`${counts[sev]} ${sev}`); }
        console.log(`  ${c.dim}${fc} findings: ${parts.join(', ')}${c.reset}`);
      } else {
        console.log(`  ${c.green}No findings${c.reset}`);
      }
      console.log();
    }

    // Consensus comparison
    if (reports.length > 1) {
      console.log(sectionHeader('Consensus'));

      // Risk range
      const risks = reports.map(r => r.report.risk_score || 0);
      const minRisk = Math.min(...risks);
      const maxRisk = Math.max(...risks);
      const avgRisk = Math.round(risks.reduce((a, b) => a + b, 0) / risks.length);
      console.log(`  Risk: ${riskBadge(avgRisk)} ${c.dim}(range ${minRisk}–${maxRisk})${c.reset}`);
      console.log();

      // Severity agreement
      const severities = reports.map(r => (r.report.max_severity || 'none').toLowerCase());
      const allSameSev = severities.every(s => s === severities[0]);
      if (allSameSev) {
        console.log(`  ${c.green}${reports.length}/${reports.length} models agree:${c.reset} ${severities[0].toUpperCase()}`);
      } else {
        console.log(`  ${c.yellow}Models disagree on severity:${c.reset}`);
        for (const { name, report } of reports) {
          const sev = (report.max_severity || 'none').toUpperCase();
          const sc = severityColor(report.max_severity);
          console.log(`    ${sc}${sev.padEnd(10)}${c.reset} ${c.dim}${name}${c.reset}`);
        }
      }
      console.log();

      // Finding intersection (match by normalized title)
      const findingsByTitle = new Map();
      for (const { name, report } of reports) {
        for (const f of (report.findings || [])) {
          const key = (f.title || '').toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim();
          if (!key) continue;
          if (!findingsByTitle.has(key)) findingsByTitle.set(key, { title: f.title, severity: f.severity, models: [] });
          findingsByTitle.get(key).models.push(name);
        }
      }

      const shared = [...findingsByTitle.values()].filter(f => f.models.length > 1);
      const unique = [...findingsByTitle.values()].filter(f => f.models.length === 1);

      if (shared.length > 0) {
        console.log(`  ${c.bold}Shared findings (${shared.length}):${c.reset}`);
        for (const f of shared) {
          const sc = severityColor(f.severity);
          console.log(`    ${sc}┃${c.reset} ${sc}${(f.severity || '').toUpperCase().padEnd(8)}${c.reset} ${f.title} ${c.dim}(${f.models.length}/${reports.length})${c.reset}`);
        }
        console.log();
      }

      if (unique.length > 0) {
        console.log(`  ${c.bold}Unique findings (${unique.length}):${c.reset}`);
        for (const f of unique) {
          const sc = severityColor(f.severity);
          console.log(`    ${sc}┃${c.reset} ${sc}${(f.severity || '').toUpperCase().padEnd(8)}${c.reset} ${f.title} ${c.dim}(${f.models[0]} only)${c.reset}`);
        }
        console.log();
      }
    }

    // Upload each report
    const noUpload = process.argv.includes('--no-upload');
    const creds = loadCredentials();
    if (!noUpload && creds) {
      for (const { report } of reports) await uploadReport(report, creds);
      console.log(`  ${c.dim}Reports: ${REGISTRY_URL}/packages/${slug}${c.reset}`);
    } else if (!noUpload && !creds) {
      console.log(`  ${c.dim}Run ${c.cyan}agentaudit login${c.dim} to upload reports to agentaudit.dev${c.reset}`);
    }

    console.log();
    return reports.map(r => r.report);
  }

  // ── Single-Model Path ────────────────────────────────────
  // If --models has exactly 1 model, use it; otherwise resolve via --model / config / env
  let activeLlm;
  if (modelNames.length === 1) {
    activeLlm = resolveModel(modelNames[0]);
  } else {
    // Model override: --model flag > AGENTAUDIT_MODEL env > credentials.json > provider default
    const modelArgIdx2 = process.argv.indexOf('--model');
    const modelFlag2 = modelArgIdx2 !== -1 ? process.argv[modelArgIdx2 + 1] : null;
    const modelOverride = modelFlag2 || process.env.AGENTAUDIT_MODEL || loadLlmConfig()?.llm_model || null;
    if (modelOverride) {
      // Route through resolveModel() so slash-models go to OpenRouter, prefixes to native providers
      activeLlm = resolveModel(modelOverride);
    }
    if (!activeLlm) {
      activeLlm = resolveProvider();
    }
  }

  if (!activeLlm) {
    // Check if user is logged in — offer remote scan as fallback
    const _creds = loadCredentials();
    if (_creds && process.stdin.isTTY && !process.argv.includes('--export')) {
      console.log();
      console.log(`  ${c.yellow}No LLM API key configured.${c.reset}`);
      console.log();
      // Fetch quota for display
      let quotaLabel = '3/day free';
      try {
        const qr = await fetch(`${REGISTRY_URL}/api/scan`, {
          headers: { 'Authorization': `Bearer ${_creds.api_key}` },
          signal: AbortSignal.timeout(5_000),
        });
        if (qr.ok) {
          const q = await qr.json();
          quotaLabel = `${q.remaining}/${q.limit} free remaining`;
        }
      } catch {}
      console.log(`  ${c.cyan}1${c.reset}  Use agentaudit.dev ${c.dim}(${quotaLabel})${c.reset}`);
      console.log(`  ${c.cyan}2${c.reset}  Configure local LLM ${c.dim}(agentaudit model)${c.reset}`);
      console.log();
      const _choice = await askQuestion(`  Choice ${c.dim}(1/2, default: 1):${c.reset} `);
      console.log();
      if (_choice.trim() === '2') {
        console.log(`  ${c.dim}Run ${c.cyan}agentaudit model${c.dim} to configure your LLM provider and API key.${c.reset}`);
        console.log();
        return null;
      }
      // Default: remote audit
      return await remoteAudit(url);
    }

    // Not logged in or non-interactive
    console.log();
    if (!_creds) {
      console.log(`  ${c.yellow}No LLM API key found.${c.reset} To run a deep audit, you need either:`);
      console.log();
      console.log(`  ${c.bold}1.${c.reset} An LLM API key:  ${c.cyan}agentaudit model${c.reset}`);
      console.log(`  ${c.bold}2.${c.reset} A free account:   ${c.cyan}agentaudit login${c.reset}  ${c.dim}(3 free remote scans/day)${c.reset}`);
    } else {
      console.log(`  ${c.yellow}No LLM API key found.${c.reset} The ${c.bold}audit${c.reset} command needs an LLM to analyze code.`);
      console.log();
      console.log(`  ${c.bold}Set an API key${c.reset} (e.g. ${c.cyan}export OPENROUTER_API_KEY=sk-or-...${c.reset})`);
      console.log(`  ${c.dim}Run "agentaudit model" to configure provider + model interactively${c.reset}`);
      console.log(`  ${c.dim}Or use ${c.cyan}agentaudit audit ${url} --remote${c.dim} for a free server-side scan${c.reset}`);
    }
    console.log();
    if (process.argv.includes('--export')) {
      const exportPath = path.join(process.cwd(), `audit-${slug}.md`);
      const exportContent = [
        `# Security Audit: ${slug}`, `**Source:** ${url}`, `**Files:** ${files.length}`, ``,
        `## Audit Instructions`, ``, auditPrompt || '(audit prompt not found)', ``,
        `## Report Format`, ``, `After analysis, produce a JSON report:`,
        '```json', `{ "skill_slug": "${slug}", "source_url": "${url}", "risk_score": 0, "result": "safe", "findings": [] }`, '```',
        ``, `## Source Code`, ``, codeBlock,
      ].join('\n');
      fs.writeFileSync(exportPath, exportContent);
      console.log(`  ${icons.safe}  Exported to ${c.bold}${exportPath}${c.reset}`);
      console.log(`  ${c.dim}Paste this into any LLM (Claude, ChatGPT, etc.) for analysis${c.reset}`);
    }
    return null;
  }

  // Single LLM call via callLlm()
  const modelLabel = `${activeLlm.name} → ${activeLlm.model}`;
  process.stdout.write(`  ${stepProgress(4, 4)} Running LLM analysis ${c.dim}(${modelLabel})${c.reset}...`);

  const llmResult = await callLlm(activeLlm, systemPrompt, userMessage);

  if (llmResult.error) {
    console.log(` ${c.red}failed${c.reset}`);
    console.log(`  ${c.red}${llmResult.error}${c.reset}`);
    if (llmResult.hint) console.log(`  ${c.dim}${llmResult.hint}${c.reset}`);
    return null;
  }

  console.log(` ${c.green}done${c.reset} ${c.dim}(${elapsed(start)})${c.reset}`);

  if (llmResult.truncated) {
    console.log();
    console.log(`  ${c.yellow}⚠ WARNING: The model's output was truncated (hit token limit).${c.reset}`);
    console.log(`  ${c.yellow}  Some findings may be missing from this scan.${c.reset}`);
    console.log(`  ${c.dim}  Tip: Try a model with more output capacity or scan a smaller package.${c.reset}`);
  }

  const report = llmResult.report;
  if (!report) {
    console.log(`  ${c.red}Could not parse LLM response as JSON${c.reset}`);
    console.log(`  ${c.dim}Hint: run with --debug to see the raw LLM response${c.reset}`);
    if (process.argv.includes('--debug')) {
      console.log(`  ${c.dim}--- Raw LLM response (first 2000 chars) ---${c.reset}`);
      console.log((llmResult.text || '(empty)').slice(0, 2000));
      console.log(`  ${c.dim}--- end ---${c.reset}`);
    }
    return null;
  }

  enrichReport(report);
  enrichFindings(report, files, pkgInfo);

  // ── Pass 2: Verification ──────────────────────────────
  const verifyArg = process.argv.find(a => a === '--verify' || a.startsWith('--verify='));
  const noVerify = process.argv.includes('--no-verify');

  let verificationResult = null;
  if (verifyArg && !noVerify && report.findings && report.findings.length > 0) {
    // Resolve verifier model
    let verifierConfig;
    const verifyValue = verifyArg.includes('=') ? verifyArg.split('=')[1] : process.argv[process.argv.indexOf('--verify') + 1];

    if (verifyValue === 'cross') {
      // Cross-model: pick a different model than the scanner
      const crossModels = ['sonnet', 'haiku', 'gemini', 'gpt-4o'];
      const scannerName = (activeLlm.name || '').toLowerCase();
      const crossModel = crossModels.find(m => !scannerName.includes(m)) || crossModels[0];
      verifierConfig = resolveModel(crossModel);
    } else if (verifyValue === 'self' || verifyValue === '--' || !verifyValue || verifyValue.startsWith('-')) {
      // Self-verification: same model
      verifierConfig = activeLlm;
    } else {
      // Specific model name
      verifierConfig = resolveModel(verifyValue);
    }

    if (!verifierConfig) {
      console.log(`  ${c.yellow}⚠ Verification skipped: no API key for verifier model${c.reset}`);
    } else {
      const verifyMode = verifierConfig === activeLlm ? 'self' : 'cross';
      const verifyLabel = `${verifierConfig.name} → ${verifierConfig.model}`;
      console.log();
      process.stdout.write(`  ${stepProgress(5, 5)} Verifying findings ${c.dim}(${verifyMode}, ${verifyLabel})${c.reset}...`);

      const vStart = Date.now();
      verificationResult = await verifyFindings(report.findings, files, verifierConfig, { maxFindings: 10 });
      const vDuration = Math.round((Date.now() - vStart) / 1000);

      console.log(` ${c.green}done${c.reset} ${c.dim}(${vDuration}s)${c.reset}`);

      // Show per-finding verification results
      for (const f of verificationResult.rejected) {
        console.log(`    ${c.red}✗${c.reset} ${(f.title || '').slice(0, 50).padEnd(52)} ${c.red}rejected${c.reset} ${c.dim}(${f.verification_reasoning?.slice(0, 60) || ''})${c.reset}`);
      }
      for (const f of verificationResult.demoted) {
        console.log(`    ${c.yellow}↓${c.reset} ${(f.title || '').slice(0, 50).padEnd(52)} ${c.yellow}demoted${c.reset} ${c.dim}(${f.original_severity} → ${f.severity})${c.reset}`);
      }
      for (const f of verificationResult.verified) {
        console.log(`    ${c.green}✓${c.reset} ${(f.title || '').slice(0, 50).padEnd(52)} ${c.green}verified${c.reset} ${c.dim}(${f.verified_confidence || f.confidence || 'medium'})${c.reset}`);
      }

      console.log(`    ${c.dim}${verificationResult.stats.verified} verified, ${verificationResult.stats.demoted} demoted, ${verificationResult.stats.rejected} rejected${c.reset}`);

      // Apply: replace findings with verified set (rejected are removed)
      const findingsBeforeVerification = report.findings.length;
      report.findings = verificationResult.finalFindings;
      report.findings_count = report.findings.length;

      // Recalculate risk score after verification
      const recalcRisk = report.findings.reduce((sum, f) => {
        if (f.by_design) return sum;
        return sum + Math.abs(f.score_impact || SEVERITY_IMPACT[f.severity] || -5);
      }, 0);
      report.risk_score = Math.min(100, recalcRisk);
      report.max_severity = report.findings.length > 0
        ? report.findings.reduce((max, f) => {
            const order = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
            return (order[f.severity] || 0) > (order[max] || 0) ? f.severity : max;
          }, 'info')
        : 'none';
      if (report.risk_score <= 25) report.result = 'safe';
      else if (report.risk_score <= 50) report.result = 'caution';
      else report.result = 'unsafe';

      // Add verification metadata to report
      report.verification_pass = true;
      report.verification_model = verifierConfig.model;
      report.verification_mode = verifyMode;
      report.verification_duration_ms = Date.now() - vStart;
      report.findings_before_verification = findingsBeforeVerification;
      report.findings_rejected = verificationResult.stats.rejected;
      report.findings_demoted = verificationResult.stats.demoted;
      report.findings_verified = verificationResult.stats.verified;
    }
  }

  saveHistory(report);

  // Display results
  console.log();
  console.log(sectionHeader('Result'));
  console.log(`  ${riskBadge(report.risk_score || 0)}`);
  console.log();

  if (report.findings && report.findings.length > 0) {
    const rejectedNote = verificationResult ? ` ${c.dim}[${verificationResult.stats.rejected} rejected by verification]${c.reset}` : '';
    console.log(sectionHeader(`Findings (${report.findings.length})`) + rejectedNote);
    console.log();
    for (const f of report.findings) {
      const sc = severityColor(f.severity);
      let badge = '';
      if (f.verification_status === 'verified') badge = ` ${c.green}✓${c.reset}`;
      else if (f.verification_status === 'demoted') badge = ` ${c.yellow}↓${c.reset}${c.dim}was ${f.original_severity}${c.reset}`;
      console.log(`  ${sc}┃${c.reset} ${sc}${(f.severity || '').toUpperCase().padEnd(8)}${c.reset}  ${c.bold}${f.title}${c.reset}${badge}`);
      if (f.file) console.log(`  ${sc}┃${c.reset}           ${c.dim}${f.file}${f.line ? ':' + f.line : ''}${c.reset}`);
      if (f.description) console.log(`  ${sc}┃${c.reset}           ${c.dim}${f.description.slice(0, 120)}${c.reset}`);
      console.log();
    }
    const histLines = severityHistogram(report.findings);
    if (histLines.length > 1) {
      console.log(sectionHeader('Severity'));
      for (const line of histLines) console.log(line);
      console.log();
    }
  } else {
    console.log(`  ${c.green}No findings — package looks clean.${c.reset}`);
    console.log();
  }

  // Upload to registry
  const noUpload = process.argv.includes('--no-upload');
  let creds = loadCredentials();
  if (noUpload) {
    // Skip silently
  } else if (creds) {
    await uploadReport(report, creds);
    console.log(`  ${c.dim}Report: ${REGISTRY_URL}/packages/${slug}${c.reset}`);
  } else if (process.stdin.isTTY) {
    console.log();
    console.log(`  ${c.bold}Want to upload this report to agentaudit.dev?${c.reset}`);
    console.log(`  ${c.dim}Create an API key at ${c.cyan}${REGISTRY_URL}/profile${c.dim} (sign in with GitHub)${c.reset}`);
    console.log();
    const pastedKey = await askQuestion(`  Paste API key ${c.dim}(or Enter to skip)${c.reset}: `);
    if (pastedKey && pastedKey.trim()) {
      process.stdout.write(`  Validating...`);
      const validation = await validateApiKey(pastedKey.trim());
      if (validation.valid) {
        const agentName = validation.agent_name || 'agent';
        saveCredentials({ api_key: pastedKey.trim(), agent_name: agentName });
        creds = { api_key: pastedKey.trim(), agent_name: agentName };
        console.log(` ${c.green}valid!${c.reset}`);
        await uploadReport(report, creds);
        console.log(`  ${c.dim}Report: ${REGISTRY_URL}/packages/${slug}${c.reset}`);
      } else {
        console.log(` ${c.red}invalid key${c.reset}`);
        console.log(`  ${c.dim}Run ${c.cyan}agentaudit login${c.dim} to sign in.${c.reset}`);
      }
    }
  } else {
    console.log(`  ${c.dim}Run ${c.cyan}agentaudit login${c.dim} to sign in and upload reports${c.reset}`);
  }

  console.log();
  return report;

  } finally {
    console.log = _origConsoleLog;
    process.stdout.write = _origStdoutWrite;
  }
}

// ── Remote Audit (server-side free scan via SSE) ────────

async function remoteAudit(url) {
  // 1. Check credentials
  const creds = loadCredentials();
  if (!creds) {
    console.log();
    console.log(`  ${c.red}Not logged in.${c.reset} Remote scans require an agentaudit.dev account.`);
    console.log(`  ${c.dim}Run ${c.cyan}agentaudit login${c.dim} to sign in (free).${c.reset}`);
    console.log();
    return null;
  }

  const authHeaders = { 'Authorization': `Bearer ${creds.api_key}`, 'Content-Type': 'application/json' };

  // 2. Check quota
  if (!quietMode) {
    try {
      const quotaRes = await fetch(`${REGISTRY_URL}/api/scan`, {
        headers: authHeaders,
        signal: AbortSignal.timeout(10_000),
      });
      if (quotaRes.ok) {
        const quota = await quotaRes.json();
        if (quota.remaining <= 0) {
          console.log();
          console.log(`  ${c.red}Rate limit reached${c.reset} — 0 of ${quota.limit} free remote scans remaining.`);
          console.log(`  ${c.dim}Configure a local LLM for unlimited scans: ${c.cyan}agentaudit model${c.reset}`);
          console.log();
          return null;
        }
        console.log(`  ${c.dim}Remote scans: ${quota.remaining} of ${quota.limit} remaining today${c.reset}`);
      }
    } catch {
      // Quota check failed — continue, the POST will catch it
    }
  }

  // 3. Start SSE stream
  if (!quietMode) {
    console.log();
    console.log(sectionHeader('Remote Audit'));
    console.log(`  ${c.dim}Server: ${REGISTRY_URL}  •  Model: Gemini 2.5 Flash${c.reset}`);
    console.log();
  }

  const startTime = Date.now();
  let report = null;

  try {
    const res = await fetch(`${REGISTRY_URL}/api/scan`, {
      method: 'POST',
      headers: authHeaders,
      body: JSON.stringify({ url }),
      signal: AbortSignal.timeout(90_000),
    });

    if (!res.ok) {
      let errBody;
      try { errBody = await res.json(); } catch { errBody = { error: `HTTP ${res.status}` }; }
      console.log(`  ${c.red}${errBody.message || errBody.error || `Server error (${res.status})`}${c.reset}`);
      console.log();
      return null;
    }

    // 4. Parse SSE stream
    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';
    const findings = [];
    let currentStep = '';

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });

      const parts = buffer.split('\n\n');
      buffer = parts.pop(); // keep incomplete chunk

      for (const part of parts) {
        const eventMatch = part.match(/^event:\s*(.+)/m);
        if (!eventMatch) continue;
        // Accumulate all data: lines per SSE spec (data fields can span multiple lines)
        const dataLines = [];
        for (const line of part.split('\n')) {
          const dm = line.match(/^data:\s?(.*)/);
          if (dm) dataLines.push(dm[1]);
        }
        if (dataLines.length === 0) continue;
        const dataStr = dataLines.join('\n');

        const event = eventMatch[1].trim();
        let data;
        try { data = JSON.parse(dataStr); } catch { continue; }

        switch (event) {
          case 'step': {
            if (quietMode) break;
            const icon = data.status === 'done' ? `${c.green}✔${c.reset}` : `${c.cyan}◌${c.reset}`;
            const detail = data.detail ? ` ${c.dim}(${data.detail})${c.reset}` : '';
            // Clear previous line if updating same step
            if (currentStep && data.status === 'done') {
              process.stdout.write(`\r\x1b[K`);
            }
            if (data.status === 'done') {
              console.log(`  ${icon} ${data.label}${detail}`);
              currentStep = '';
            } else {
              process.stdout.write(`\r  ${icon} ${data.label}${detail}`);
              currentStep = data.label;
            }
            break;
          }

          case 'finding': {
            findings.push(data);
            break;
          }

          case 'cached': {
            if (!quietMode) {
              console.log(`  ${c.cyan}ℹ${c.reset} Using cached result from ${c.bold}${data.scanned_ago}${c.reset}`);
            }
            break;
          }

          case 'result': {
            report = {
              cached: data.cached,
              result: data.result,
              risk_score: data.risk_score,
              trust_score: data.trust_score,
              findings_count: data.findings_count,
              max_severity: data.max_severity,
              slug: data.slug,
              url: data.url,
              findings: findings,
              audit_model: 'google/gemini-2.5-flash',
              audit_provider: 'agentaudit.dev',
              source_url: url,
              skill_slug: data.slug,
              audit_duration_ms: Date.now() - startTime,
            };
            break;
          }

          case 'error': {
            if (currentStep) {
              process.stdout.write(`\r\x1b[K`);
              currentStep = '';
            }
            console.log(`  ${c.red}${data.message || 'Server error'}${c.reset}`);
            break;
          }

          case 'done':
            break;
        }
      }
    }
  } catch (err) {
    if (err.name === 'TimeoutError' || err.name === 'AbortError') {
      console.log(`  ${c.red}Timeout — server took too long to respond.${c.reset}`);
    } else {
      console.log(`  ${c.red}Connection error: ${err.message}${c.reset}`);
    }
    console.log();
    return null;
  }

  if (!report) {
    console.log(`  ${c.red}No result received from server.${c.reset}`);
    console.log();
    return null;
  }

  // 5. Display results
  if (!quietMode) {
    console.log();
    console.log(sectionHeader('Result'));
    console.log(`  ${riskBadge(report.risk_score || 0)}`);
    console.log();

    if (findings.length > 0) {
      console.log(sectionHeader(`Findings (${findings.length})`));
      console.log();
      for (const f of findings) {
        const sc = severityColor(f.severity);
        console.log(`  ${sc}┃${c.reset} ${sc}${(f.severity || '').toUpperCase().padEnd(8)}${c.reset}  ${c.bold}${f.title}${c.reset}`);
        if (f.file) console.log(`  ${sc}┃${c.reset}           ${c.dim}${f.file}${f.line ? ':' + f.line : ''}${c.reset}`);
        console.log();
      }
    } else {
      console.log(`  ${c.green}No findings — package looks clean.${c.reset}`);
      console.log();
    }

    console.log(`  ${c.dim}Report: ${REGISTRY_URL}/packages/${report.slug}${c.reset}`);
    console.log(`  ${c.dim}Duration: ${elapsed(startTime)}${c.reset}`);
    console.log();
  }

  // JSON output
  if (jsonMode && !quietMode) {
    console.log(JSON.stringify(report, null, 2));
  }

  return report;
}

// ── Check command ───────────────────────────────────────

async function checkPackage(name) {
  if (!jsonMode) {
    console.log(`${icons.info}  Looking up ${c.bold}${name}${c.reset} in registry...`);
    console.log();
  }
  
  const data = await checkRegistry(name);
  if (!data) {
    if (!jsonMode) {
      console.log(`  ${c.yellow}Not found${c.reset} — package "${name}" hasn't been audited yet.`);
      console.log(`  ${c.dim}Run: agentaudit audit <repo-url> for a deep LLM audit${c.reset}`);
      await suggestSimilarPackages(name);
    }
    return null;
  }
  
  if (!jsonMode) {
    const riskScore = data.risk_score ?? data.latest_risk_score ?? 0;
    console.log(`  ${c.bold}${name}${c.reset}  ${riskBadge(riskScore)}`);
    console.log(`  ${c.dim}Risk Score: ${riskScore}/100${c.reset}`);
    if (data.source_url) console.log(`  ${c.dim}Source: ${data.source_url}${c.reset}`);
    console.log(`  ${c.dim}Registry: ${REGISTRY_URL}/packages/${name}${c.reset}`);
    if (data.has_official_audit) console.log(`  ${c.green}✔ Officially audited${c.reset}`);
    console.log();
  }
  return data;
}

// ── Dashboard / Leaderboard / Benchmark Commands ────────

async function fetchDashboardData() {
  const creds = loadCredentials();
  const fetches = [
    fetch(`${REGISTRY_URL}/api/stats`, { signal: AbortSignal.timeout(15_000) }).then(r => r.ok ? r.json() : null).catch(() => null),
    fetch(`${REGISTRY_URL}/api/leaderboard?limit=50`, { signal: AbortSignal.timeout(15_000) }).then(r => r.ok ? r.json() : null).catch(() => null),
    fetch(`${REGISTRY_URL}/api/benchmark`, { signal: AbortSignal.timeout(15_000) }).then(r => r.ok ? r.json() : null).catch(() => null),
  ];
  if (creds?.agent_name && creds.agent_name !== 'env') {
    fetches.push(
      fetch(`${REGISTRY_URL}/api/agents/${encodeURIComponent(creds.agent_name)}`, {
        headers: { 'Authorization': `Bearer ${creds.api_key}` },
        signal: AbortSignal.timeout(15_000),
      }).then(r => r.ok ? r.json() : null).catch(() => null)
    );
  } else {
    fetches.push(Promise.resolve(null));
  }
  const [stats, leaderboard, benchmark, agent] = await Promise.all(fetches);
  // Update profile cache if we have agent data
  if (agent && creds) {
    let rank = null;
    if (Array.isArray(leaderboard)) {
      const idx = leaderboard.findIndex(e => e.agent_name === creds.agent_name);
      if (idx >= 0) rank = idx + 1;
    }
    saveProfileCache({
      agent_name: creds.agent_name,
      rank,
      total_points: agent.total_points || 0,
      total_reports: agent.total_reports || 0,
    });
  }
  return { stats, leaderboard, benchmark, agent, creds };
}

const QUICK_ACTIONS = [
  { key: 'a', label: 'Audit', arg: '<url>', desc: 'Deep LLM security audit', cmd: 'audit' },
  { key: 'v', label: 'Audit --verify', arg: '<url>', desc: 'Audit + adversarial verification', cmd: 'audit-verify' },
  { key: 'r', label: 'Remote scan', arg: '<url>', desc: 'Server-side scan (no API key)', cmd: 'remote' },
  { key: 'c', label: 'Consensus', arg: '<pkg>', desc: 'Cross-model consensus view', cmd: 'consensus' },
];

function renderOverviewTab(data, width, quickActionIdx = -1) {
  const { stats, agent, leaderboard, creds } = data;
  const lines = [];
  const halfW = Math.min(Math.floor((width - 6) / 2), 40);

  // Profile box
  const profileLines = [];
  if (agent && creds) {
    // Find rank
    let rank = '-';
    if (leaderboard && Array.isArray(leaderboard)) {
      const idx = leaderboard.findIndex(e => e.agent_name === creds.agent_name);
      if (idx >= 0) rank = `#${idx + 1} of ${leaderboard.length}`;
    }
    const nameVis = visLen(creds.agent_name);
    const rankVis = visLen(rank);
    const nameGap = Math.max(1, halfW - nameVis - rankVis);
    profileLines.push(`${c.bold}${creds.agent_name}${c.reset}${' '.repeat(nameGap)}${c.dim}${rank}${c.reset}`);
    profileLines.push(`Points     ${c.bold}${fmtNum(agent.total_points)}${c.reset}`);
    profileLines.push(`Audits     ${c.bold}${fmtNum(agent.total_reports)}${c.reset}`);
    profileLines.push(`Findings   ${c.bold}${fmtNum(agent.total_findings_submitted)}${c.reset} ${c.dim}(${fmtNum(agent.total_findings_confirmed)} confirmed)${c.reset}`);
    const sev = agent.severity_breakdown || {};
    profileLines.push('');
    const sevParts = [];
    if (sev.critical) sevParts.push(`${c.red}${sev.critical} crit${c.reset}`);
    if (sev.high) sevParts.push(`${c.red}${sev.high} high${c.reset}`);
    if (sev.medium) sevParts.push(`${c.yellow}${sev.medium} med${c.reset}`);
    if (sev.low) sevParts.push(`${c.blue}${sev.low} low${c.reset}`);
    profileLines.push(sevParts.join('  ') || `${c.dim}no findings yet${c.reset}`);
  } else {
    profileLines.push(`${c.dim}Not logged in${c.reset}`);
    profileLines.push(`${c.dim}Run ${c.cyan}agentaudit login${c.dim} to sign in${c.reset}`);
  }

  // Registry box
  const regLines = [];
  if (stats) {
    regLines.push(`Packages Audited    ${c.bold}${fmtNum(stats.skills_audited)}${c.reset}`);
    regLines.push(`Total Findings      ${c.bold}${fmtNum(stats.total_findings)}${c.reset}`);
    regLines.push(`Total Reports       ${c.bold}${fmtNum(stats.total_reports)}${c.reset}`);
    regLines.push(`Contributors        ${c.bold}${fmtNum(stats.reporters)}${c.reset}`);
    regLines.push(`Avg Trust Score     ${c.bold}${stats.avg_trust_score || 0}${c.reset}`);
    regLines.push('');
    const parts = [];
    if (stats.safe_packages) parts.push(`${c.green}●${fmtNum(stats.safe_packages)} safe${c.reset}`);
    if (stats.caution_packages) parts.push(`${c.yellow}●${fmtNum(stats.caution_packages)} caution${c.reset}`);
    if (stats.unsafe_packages) parts.push(`${c.red}●${fmtNum(stats.unsafe_packages)} unsafe${c.reset}`);
    regLines.push(parts.join('  ') || `${c.dim}no packages yet${c.reset}`);
  } else {
    regLines.push(`${c.dim}Could not load registry stats${c.reset}`);
  }

  // Local history stats
  const localHistory = loadHistory(50);
  const verifiedCount = localHistory.filter(h => h.verification).length;
  const localStats = {
    total: localHistory.length,
    verified: verifiedCount,
    lastAudit: localHistory[0] ? timeAgo(localHistory[0].timestamp || localHistory[0].date) : null,
  };

  const boxW = halfW + 4;
  const profileBox = drawBox('Your Profile', profileLines, boxW);
  const registryBox = drawBox('Registry', regLines, boxW);

  // Side by side if wide enough, stacked otherwise
  if (width >= boxW * 2 + 4) {
    const maxLen = Math.max(profileBox.length, registryBox.length);
    // Insert filler lines BEFORE the bottom border (last line), not after
    while (profileBox.length < maxLen) {
      profileBox.splice(profileBox.length - 1, 0, `  ${BOX.v} ${' '.repeat(halfW + 1)}${BOX.v}`);
    }
    while (registryBox.length < maxLen) {
      registryBox.splice(registryBox.length - 1, 0, `  ${BOX.v} ${' '.repeat(halfW + 1)}${BOX.v}`);
    }
    for (let i = 0; i < maxLen; i++) {
      lines.push(profileBox[i] + '  ' + registryBox[i].trimStart());
    }
  } else {
    lines.push(...profileBox, '', ...registryBox);
  }

  // Local history section
  lines.push('');
  if (localStats.total > 0) {
    const histParts = [`${c.bold}${localStats.total}${c.reset} local audits`];
    if (localStats.verified > 0) histParts.push(`${c.green}${localStats.verified} verified${c.reset}`);
    if (localStats.lastAudit) histParts.push(`${c.dim}last: ${localStats.lastAudit}${c.reset}`);
    lines.push(`  ${c.dim}Local:${c.reset} ${histParts.join(`  ${c.dim}│${c.reset}  `)}`);
  }

  // Quick actions (interactive)
  lines.push('');
  lines.push(`  ${c.bold}Quick Actions${c.reset}  ${c.dim}(press key or Enter to launch)${c.reset}`);
  for (let i = 0; i < QUICK_ACTIONS.length; i++) {
    const qa = QUICK_ACTIONS[i];
    const isSel = i === quickActionIdx;
    const pointer = isSel ? `${c.cyan}\u276F${c.reset}` : ' ';
    const keyBadge = `${c.dim}[${c.reset}${c.cyan}${qa.key}${c.reset}${c.dim}]${c.reset}`;
    const label = isSel ? `${c.bold}${c.cyan}${qa.label} ${qa.arg}${c.reset}` : `${qa.label} ${c.dim}${qa.arg}${c.reset}`;
    lines.push(` ${pointer} ${keyBadge}  ${label}  ${c.dim}${qa.desc}${c.reset}`);
  }

  return lines;
}

function renderLeaderboardTab(data, width, opts = {}) {
  const { leaderboard, creds } = data;
  const lines = [];
  const maxNameW = 20;
  const barW = Math.min(Math.max(10, width - 70), 30);

  if (!leaderboard || !Array.isArray(leaderboard) || leaderboard.length === 0) {
    lines.push(`  ${c.dim}No leaderboard data available${c.reset}`);
    return lines;
  }

  const maxPts = leaderboard[0]?.total_points || 1;
  const medals = [`${c.yellow}★${c.reset}`, `${c.cyan}★${c.reset}`, `${c.magenta}★${c.reset}`];

  for (let i = 0; i < leaderboard.length; i++) {
    const entry = leaderboard[i];
    const name = (entry.agent_name || '').slice(0, maxNameW);
    const isMe = creds && entry.agent_name === creds.agent_name;
    const prefix = i < 3 ? `  ${medals[i]}   ` : `  ${c.dim}#${String(i + 1).padStart(2)}${c.reset} `;
    const nameStr = isMe ? `${c.green}${c.bold}${name}${c.reset}` : name;
    const bar = renderBar(entry.total_points || 0, maxPts, barW);
    const pts = padLeft(`${fmtNum(entry.total_points || 0)} pts`, 12);
    const audits = padLeft(`${fmtNum(entry.total_reports || 0)} audits`, 12);
    const extra = entry.monthly_reports != null ? padLeft(`${fmtNum(entry.monthly_reports)} this mo`, 12) : '';
    lines.push(`${prefix}${padRight(nameStr, maxNameW)}  ${bar}  ${pts}  ${audits}${extra}`);

    // Separator after top 3
    if (i === 2 && leaderboard.length > 3) {
      lines.push(`  ${c.dim}${'─'.repeat(Math.min(width - 4, 76))}${c.reset}`);
    }
  }

  // Highlight current user if not in top list
  if (creds && !leaderboard.find(e => e.agent_name === creds.agent_name)) {
    lines.push('');
    lines.push(`  ${c.dim}← you are not on this leaderboard yet${c.reset}`);
  }

  return lines;
}

function renderBenchmarkTab(data, width) {
  const { benchmark } = data;
  const lines = [];

  if (!benchmark || !benchmark.models || benchmark.models.length === 0) {
    lines.push(`  ${c.dim}No benchmark data available${c.reset}`);
    return lines;
  }

  const overview = benchmark.overview || {};
  lines.push(`  ${c.bold}${fmtNum(benchmark.models.length)}${c.reset} models ${c.dim}│${c.reset} ${c.bold}${fmtNum(overview.total_reports || 0)}${c.reset} audits ${c.dim}│${c.reset} ${c.bold}${fmtNum(overview.total_findings || 0)}${c.reset} findings`);
  lines.push('');

  // Header — fixed column widths for alignment
  const nameW = 30;
  const auditsW = 6;
  const riskW = 5;
  const hdr = `  ${padRight('Model', nameW)}  ${padLeft('Audits', auditsW)}  ${padLeft('Risk', riskW)}  ${'Detection'.padEnd(14)}  Severity`;
  lines.push(`  ${c.bold}${stripAnsi(hdr).trim()}${c.reset}`);
  lines.push(`  ${c.dim}${'─'.repeat(Math.min(width - 4, 86))}${c.reset}`);

  for (const m of benchmark.models) {
    const name = (m.audit_model || 'unknown').slice(0, nameW - 2);
    const audits = padLeft(fmtNum(m.total_audits), auditsW);
    const riskVal = parseFloat(m.avg_risk_score) || 0;
    const riskColor = riskVal <= 20 ? c.green : riskVal <= 40 ? c.yellow : c.red;
    const risk = `${riskColor}${padLeft(String(Math.round(riskVal)), riskW)}${c.reset}`;
    const detection = renderGauge(m.detection_rate || 0, 100, 10);
    // Severity as compact text
    const sev = m.severity_breakdown || {};
    const sevParts = [];
    if (sev.critical) sevParts.push(`${c.red}${sev.critical}C${c.reset}`);
    if (sev.high) sevParts.push(`${c.red}${sev.high}H${c.reset}`);
    if (sev.medium) sevParts.push(`${c.yellow}${sev.medium}M${c.reset}`);
    if (sev.low) sevParts.push(`${c.blue}${sev.low}L${c.reset}`);
    const sevStr = sevParts.length > 0 ? sevParts.join(' ') : `${c.dim}—${c.reset}`;
    lines.push(`  ${padRight(name, nameW)}  ${audits}  ${risk}  ${detection}  ${sevStr}`);
  }

  // Vulnerability landscape
  const cats = benchmark.global_categories;
  if (cats && cats.length > 0) {
    lines.push('');
    const catTotal = cats.reduce((sum, cat) => sum + (cat.count || 0), 0) || 1;
    const catW = Math.min(width - 8, 56);
    const catLines = [];
    for (const cat of cats.slice(0, 6)) {
      const pct = Math.round((cat.count / catTotal) * 100);
      const barFill = Math.round((cat.count / catTotal) * (catW - 30));
      catLines.push(`${padRight(cat.category || 'Other', 22)} ${c.cyan}${'█'.repeat(Math.max(1, barFill))}${c.dim}${'░'.repeat(Math.max(0, catW - 30 - barFill))}${c.reset}  ${padLeft(fmtPct(pct), 4)}`);
    }
    lines.push(...drawBox('Vulnerability Landscape', catLines, catW + 4));
  }

  // Cross-model findings
  const cross = benchmark.cross_model_findings;
  if (cross && cross.length > 0) {
    lines.push('');
    lines.push(`  ${c.bold}Cross-Model Findings${c.reset} ${c.dim}(confirmed by multiple models)${c.reset}`);
    for (const cf of cross.slice(0, 5)) {
      const models = (cf.models || []).slice(0, 3).join(', ');
      lines.push(`  ${c.dim}•${c.reset} ${cf.title || cf.pattern_id}  ${c.dim}[${cf.model_count} models: ${models}]${c.reset}`);
    }
  }

  return lines;
}

function timeAgo(dateStr) {
  if (!dateStr) return '';
  const diff = Date.now() - new Date(dateStr).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 30) return `${days}d ago`;
  return `${Math.floor(days / 30)}mo ago`;
}

function renderActivityTab(data, width) {
  const { agent, creds } = data;
  const lines = [];

  if (!creds || !agent) {
    lines.push(`  ${c.dim}Not logged in${c.reset}`);
    lines.push(`  ${c.dim}Run ${c.cyan}agentaudit setup${c.dim} to see your activity${c.reset}`);
    return lines;
  }

  // Recent Audits
  const reports = agent.recent_reports || [];
  const auditLines = [];
  if (reports.length > 0) {
    for (const r of reports.slice(0, 10)) {
      const time = padRight(timeAgo(r.created_at), 8);
      const name = padRight((r.skill_slug || r.package_name || '').slice(0, 20), 20);
      const score = r.risk_score ?? r.latest_risk_score ?? 0;
      let status;
      if (score === 0) status = `${c.green}safe${c.reset}   `;
      else if (score <= 30) status = `${c.yellow}caution${c.reset}`;
      else status = `${c.red}unsafe${c.reset} `;
      const findCount = r.finding_count != null ? `${r.finding_count} findings` : '';
      const model = r.audit_model ? `${c.dim}${(r.audit_model || '').slice(0, 14)}${c.reset}` : '';
      auditLines.push(`${c.dim}${time}${c.reset}  ${name}  ${status}  ${padRight(findCount, 12)} ${model}`);
    }
  } else {
    auditLines.push(`${c.dim}No audits yet — run ${c.cyan}agentaudit audit <url>${c.dim} to get started${c.reset}`);
  }
  lines.push(...drawBox('Recent Audits', auditLines, Math.min(width - 4, 72)));
  lines.push('');

  // Recent Findings
  const findings = agent.recent_findings || [];
  const findingLines = [];
  if (findings.length > 0) {
    for (const f of findings.slice(0, 10)) {
      const asfId = padRight(f.asf_id || f.id || '', 16);
      const sev = severityIcon(f.severity);
      const sevLabel = padRight(f.severity || '', 9);
      const title = (f.title || f.pattern_id || '').slice(0, 40);
      findingLines.push(`${asfId} ${sev} ${sevLabel} ${title}`);
    }
  } else {
    findingLines.push(`${c.dim}No findings yet${c.reset}`);
  }
  lines.push(...drawBox('Recent Findings', findingLines, Math.min(width - 4, 72)));

  return lines;
}

async function activityCommand(args) {
  const creds = loadCredentials();

  if (!creds?.agent_name || creds.agent_name === 'env') {
    if (jsonMode) {
      console.log(JSON.stringify({ error: 'not_logged_in' }));
    } else {
      banner();
      console.log(`  ${c.yellow}Not logged in${c.reset}`);
      console.log(`  ${c.dim}Run ${c.cyan}agentaudit login${c.dim} to sign in${c.reset}`);
    }
    return;
  }

  if (!quietMode && !jsonMode) {
    banner();
    process.stdout.write(`  ${c.dim}Loading activity...${c.reset}`);
  }

  let agentData;
  try {
    const res = await fetch(`${REGISTRY_URL}/api/agents/${encodeURIComponent(creds.agent_name)}`, {
      headers: { 'Authorization': `Bearer ${creds.api_key}` },
      signal: AbortSignal.timeout(15_000),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    agentData = await res.json();
  } catch (err) {
    if (!jsonMode) {
      process.stdout.write('\r\x1b[2K');
      console.log(`  ${c.red}Failed to load activity: ${err.message}${c.reset}`);
    }
    process.exitCode = 1;
    return;
  }

  if (jsonMode) {
    console.log(JSON.stringify(agentData, null, 2));
    return;
  }

  process.stdout.write('\r\x1b[2K');

  // Update profile cache
  try {
    const lbRes = await fetch(`${REGISTRY_URL}/api/leaderboard?limit=100`, { signal: AbortSignal.timeout(10_000) }).then(r => r.ok ? r.json() : null);
    let rank = null;
    if (Array.isArray(lbRes)) {
      const idx = lbRes.findIndex(e => e.agent_name === creds.agent_name);
      if (idx >= 0) rank = idx + 1;
    }
    saveProfileCache({
      agent_name: creds.agent_name,
      rank,
      total_points: agentData.total_points || 0,
      total_reports: agentData.total_reports || 0,
    });
  } catch {}

  const width = process.stdout.columns || 80;
  const activityLines = renderActivityTab({ agent: agentData, creds }, width);
  console.log(`  ${c.bold}Activity${c.reset}  ${c.dim}${creds.agent_name}${c.reset}`);
  console.log();
  for (const line of activityLines) console.log(line);
  console.log();
}

function renderSearchResults(data, width) {
  const lines = [];
  const boxW = Math.min(width - 4, 72);

  // Lookup API returns { reports: [], findings: [], total_matches }
  const lookupData = Array.isArray(data) ? data[0] : data;
  const reports = lookupData?.reports || [];
  const findings = lookupData?.findings || [];
  const total = lookupData?.total_matches || (reports.length + findings.length);

  if (total === 0) return lines;

  // Packages (from reports)
  if (reports.length > 0) {
    const pkgLines = [];
    for (const r of reports.slice(0, 10)) {
      const name = padRight((r.skill_slug || '').slice(0, 22), 22);
      const riskScore = r.risk_score ?? 0;
      let badge;
      if (riskScore === 0) badge = `${c.green}SAFE${c.reset}   `;
      else if (riskScore <= 30) badge = `${c.yellow}CAUTION${c.reset}`;
      else badge = `${c.red}UNSAFE${c.reset} `;
      const time = padRight(timeAgo(r.created_at), 8);
      pkgLines.push(`${name}  ${badge}  ${c.dim}${time}${c.reset}`);
    }
    lines.push(...drawBox(`Packages (${reports.length})`, pkgLines, boxW));
    lines.push('');
  }

  // Findings
  if (findings.length > 0) {
    const findLines = [];
    for (const f of findings.slice(0, 10)) {
      const asfId = padRight(f.asf_id || '', 16);
      const sev = severityIcon(f.severity);
      const sevLabel = padRight(f.severity || '', 9);
      const title = (f.title || '').slice(0, 36);
      findLines.push(`${asfId} ${sev} ${sevLabel} ${title}`);
    }
    lines.push(...drawBox(`Findings (${findings.length})`, findLines, boxW));
  }

  return lines;
}

function renderSearchTab(searchState, width) {
  const { query, results, loading, error } = searchState;
  const lines = [];

  // Search input
  lines.push(`  ${c.bold}Search:${c.reset} ${query || ''}${c.dim}\u2588${c.reset}`);
  lines.push('');

  if (loading) {
    lines.push(`  ${c.dim}Searching...${c.reset}`);
    return lines;
  }

  if (error) {
    lines.push(`  ${c.red}${error}${c.reset}`);
    return lines;
  }

  if (results) {
    const resultLines = renderSearchResults(results, width);
    if (resultLines.length > 0) {
      lines.push(...resultLines);
    } else {
      lines.push(`  ${c.dim}No results found for "${query}"${c.reset}`);
    }
  } else if (!query) {
    lines.push(`  ${c.dim}Type to search packages in the registry${c.reset}`);
  }

  lines.push('');
  lines.push(`  ${c.dim}Type to search  \u2502  Enter=search  \u2502  Esc=clear  \u2502  Tab=switch tab${c.reset}`);

  return lines;
}

async function suggestSimilarPackages(slug) {
  if (jsonMode || quietMode) return;
  try {
    const res = await fetch(`${REGISTRY_URL}/api/lookup?hash=${encodeURIComponent(slug)}`, {
      signal: AbortSignal.timeout(5_000),
    });
    if (!res.ok) return;
    const data = await res.json();
    // API returns { reports: [...], findings: [...], total_matches }
    const reports = data.reports || [];
    if (reports.length === 0) return;
    console.log();
    console.log(`  ${c.dim}Did you mean one of these?${c.reset}`);
    const shown = reports.slice(0, 5);
    for (const p of shown) {
      const name = p.skill_slug || p.slug || '?';
      const risk = p.risk_score ?? 0;
      const badge = risk === 0 ? `${c.green}safe${c.reset}` : risk <= 25 ? `${c.green}score ${100 - risk}${c.reset}` : risk <= 50 ? `${c.yellow}score ${100 - risk}${c.reset}` : `${c.red}score ${100 - risk}${c.reset}`;
      console.log(`    ${c.cyan}${name}${c.reset}  ${badge}`);
    }
    if (data.total_matches > 5) console.log(`    ${c.dim}...and ${data.total_matches - 5} more${c.reset}`);
    console.log(`  ${c.dim}Use: ${c.cyan}agentaudit search <query>${c.dim} to find packages${c.reset}`);
  } catch { /* ignore */ }
}

async function searchCommand(args) {
  const query = args.filter(a => !a.startsWith('--')).join(' ').trim();

  if (!query) {
    if (jsonMode) {
      console.log(JSON.stringify({ error: 'query_required' }));
    } else {
      banner();
      console.log(`  ${c.red}Error: search query required${c.reset}`);
      console.log(`  ${c.dim}Usage: ${c.cyan}agentaudit search <query>${c.dim} \u2014 e.g. agentaudit search fastmcp${c.reset}`);
    }
    process.exitCode = 2;
    return;
  }

  if (!quietMode && !jsonMode) {
    banner();
    process.stdout.write(`  ${c.dim}Searching "${query}"...${c.reset}`);
  }

  let data;
  try {
    const res = await fetch(`${REGISTRY_URL}/api/lookup?hash=${encodeURIComponent(query)}`, {
      signal: AbortSignal.timeout(15_000),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    data = await res.json();
  } catch (err) {
    if (!jsonMode) {
      process.stdout.write('\r\x1b[2K');
      console.log(`  ${c.red}Search failed: ${err.message}${c.reset}`);
    }
    process.exitCode = 1;
    return;
  }

  if (jsonMode) {
    console.log(JSON.stringify(data, null, 2));
    return;
  }

  process.stdout.write('\r\x1b[2K');
  console.log(`  ${c.bold}Search${c.reset}  ${c.dim}"${query}"${c.reset}`);
  console.log();

  const width = process.stdout.columns || 80;
  const resultLines = renderSearchResults(data, width);
  if (resultLines.length === 0) {
    console.log(`  ${c.dim}No results found${c.reset}`);
    console.log(`  ${c.dim}Tip: try ${c.cyan}agentaudit scan <repo-url>${c.dim} to audit a new package${c.reset}`);
    console.log();
    return;
  }

  for (const line of resultLines) console.log(line);
  console.log();
}

async function leaderboardCommand(args) {
  const tabArg = args.find((a, i) => args[i - 1] === '--tab') || 'overall';
  const showAll = args.includes('--all');
  const limit = showAll ? 200 : 20;

  if (!quietMode && !jsonMode) {
    banner();
    process.stdout.write(`  ${c.dim}Loading leaderboard...${c.reset}`);
  }

  let data;
  try {
    const url = `${REGISTRY_URL}/api/leaderboard?tab=${encodeURIComponent(tabArg)}&limit=${limit}`;
    const res = await fetch(url, { signal: AbortSignal.timeout(15_000) });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    data = await res.json();
  } catch (err) {
    if (!jsonMode) {
      process.stdout.write('\r\x1b[2K');
      console.log(`  ${c.red}Failed to load leaderboard: ${err.message}${c.reset}`);
    }
    process.exitCode = 1;
    return;
  }

  if (jsonMode) {
    console.log(JSON.stringify(data, null, 2));
    return;
  }

  process.stdout.write('\r\x1b[2K');
  const creds = loadCredentials();
  console.log(`  ${c.bold}Leaderboard${c.reset}  ${c.dim}${tabArg}${c.reset}`);
  console.log();

  if (!Array.isArray(data) || data.length === 0) {
    console.log(`  ${c.dim}No data available${c.reset}`);
    return;
  }

  const maxPts = data[0]?.total_points || 1;
  const medals = [`${c.yellow}★${c.reset}`, `${c.cyan}★${c.reset}`, `${c.magenta}★${c.reset}`];
  const barW = 24;

  for (let i = 0; i < data.length; i++) {
    const entry = data[i];
    const name = (entry.agent_name || '').slice(0, 20);
    const isMe = creds && entry.agent_name === creds.agent_name;
    const prefix = i < 3 ? `  ${medals[i]}   ` : `  ${c.dim}#${String(i + 1).padStart(2)}${c.reset} `;
    const nameStr = isMe ? `${c.green}${c.bold}${name}${c.reset}` : name;
    const bar = renderBar(entry.total_points || 0, maxPts, barW);
    const pts = `${fmtNum(entry.total_points || 0)} pts`;
    const audits = `${fmtNum(entry.total_reports || 0)} audits`;
    console.log(`${prefix}${padRight(nameStr, 22)}  ${bar}  ${padLeft(pts, 12)}  ${padLeft(audits, 10)}`);
    if (i === 2 && data.length > 3) {
      console.log(`  ${c.dim}${'─'.repeat(74)}${c.reset}`);
    }
  }
  console.log();
}

async function benchmarkCommand(args) {
  if (!quietMode && !jsonMode) {
    banner();
    process.stdout.write(`  ${c.dim}Loading benchmark data...${c.reset}`);
  }

  let data;
  try {
    const res = await fetch(`${REGISTRY_URL}/api/benchmark`, { signal: AbortSignal.timeout(15_000) });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    data = await res.json();
  } catch (err) {
    if (!jsonMode) {
      process.stdout.write('\r\x1b[2K');
      console.log(`  ${c.red}Failed to load benchmark: ${err.message}${c.reset}`);
    }
    process.exitCode = 1;
    return;
  }

  if (jsonMode) {
    console.log(JSON.stringify(data, null, 2));
    return;
  }

  process.stdout.write('\r\x1b[2K');
  const width = process.stdout.columns || 80;
  const benchLines = renderBenchmarkTab({ benchmark: data }, width);
  console.log(`  ${c.bold}Model Benchmark${c.reset} ${c.dim}— LLM Audit Performance${c.reset}`);
  console.log();
  for (const line of benchLines) console.log(line);
  console.log();
}

async function dashboardCommand() {
  if (!process.stdin.isTTY || !process.stdout.isTTY) {
    console.log(`${c.red}Error: dashboard requires an interactive terminal${c.reset}`);
    console.log(`${c.dim}Tip: use ${c.cyan}agentaudit leaderboard${c.dim} or ${c.cyan}agentaudit benchmark${c.dim} for non-interactive output${c.reset}`);
    process.exitCode = 1;
    return;
  }

  const tabs = [
    { key: '1', label: 'Overview' },
    { key: '2', label: 'Leaderboard' },
    { key: '3', label: 'Benchmark' },
    { key: '4', label: 'Activity' },
    { key: '5', label: 'Search' },
  ];
  let activeTab = 0;
  let scrollOffset = 0;
  let running = true;
  let quickActionIdx = 0; // selected quick action on overview tab
  let pendingAction = null; // set when user triggers a quick action

  // Search tab state
  let searchQuery = '';
  let searchResults = null;
  let searchLoading = false;
  let searchError = null;

  // Enter alt screen
  process.stdout.write(term.altScreenOn + term.hideCursor);

  // Loading screen
  process.stdout.write(term.clearScreen);
  const bannerLines = dashboardBanner();
  for (const line of bannerLines) process.stdout.write(line + '\n');
  process.stdout.write(`\n  ${c.dim}Loading data...${c.reset}\n`);

  // Fetch data
  const data = await fetchDashboardData();

  async function doSearch() {
    if (!searchQuery.trim()) return;
    searchLoading = true;
    searchError = null;
    render();
    try {
      const res = await fetch(`${REGISTRY_URL}/api/lookup?hash=${encodeURIComponent(searchQuery.trim())}`, {
        signal: AbortSignal.timeout(15_000),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      searchResults = await res.json();
    } catch (err) {
      searchError = `Search failed: ${err.message}`;
      searchResults = null;
    }
    searchLoading = false;
    if (running) render();
  }

  function render() {
    const cols = process.stdout.columns || 80;
    const rows = process.stdout.rows || 24;
    let output = term.clearScreen;

    // Banner
    const bLines = dashboardBanner();
    for (const line of bLines) output += line + '\n';
    output += '\n';

    // Tab bar
    let tabBar = '  ';
    for (let i = 0; i < tabs.length; i++) {
      const tab = tabs[i];
      if (i === activeTab) {
        tabBar += `${c.bold}${c.cyan}${term.underline} [${tab.key}] ${tab.label} ${term.noUnderline}${c.reset}`;
      } else {
        tabBar += `${c.dim} [${tab.key}] ${tab.label} ${c.reset}`;
      }
      if (i < tabs.length - 1) tabBar += `${c.dim}\u2500${c.reset}`;
    }
    output += tabBar + '\n\n';

    // Tab content
    let contentLines = [];
    switch (activeTab) {
      case 0:
        contentLines = renderOverviewTab(data, cols, quickActionIdx);
        break;
      case 1:
        contentLines = renderLeaderboardTab(data, cols);
        break;
      case 2:
        contentLines = renderBenchmarkTab(data, cols);
        break;
      case 3:
        contentLines = renderActivityTab(data, cols);
        break;
      case 4:
        contentLines = renderSearchTab({ query: searchQuery, results: searchResults, loading: searchLoading, error: searchError }, cols);
        break;
    }

    // Apply scroll
    const availableRows = rows - 10; // header + tab bar + footer
    const maxScroll = Math.max(0, contentLines.length - availableRows);
    scrollOffset = Math.min(scrollOffset, maxScroll);
    scrollOffset = Math.max(0, scrollOffset);

    const visible = contentLines.slice(scrollOffset, scrollOffset + availableRows);
    for (const line of visible) output += line + '\n';

    // Footer
    output += '\n';
    const scrollInfo = contentLines.length > availableRows ? `  ${c.dim}[${scrollOffset + 1}-${Math.min(scrollOffset + availableRows, contentLines.length)}/${contentLines.length}]${c.reset}` : '';
    const isSearchTab = activeTab === 4;
    const isOverviewTab = activeTab === 0;
    const footerHint = isSearchTab
      ? `${c.dim}\u2190\u2192 tab  Enter=search  Esc=clear  q quit${c.reset}`
      : isOverviewTab
        ? `${c.dim}\u2190\u2192 tab  \u2191\u2193 select  Enter=launch  a/v/r/c shortcut  q quit${c.reset}`
        : `${c.dim}\u2190\u2192 tab  \u2191\u2193 scroll  1-5 jump  q quit${c.reset}`;
    output += `  ${footerHint}${scrollInfo}\n`;

    process.stdout.write(output);
  }

  function cleanup() {
    if (!running) return;
    running = false;
    process.stdout.write(term.showCursor + term.altScreenOff);
    try { process.stdin.setRawMode(false); } catch {}
    process.stdin.pause();
    process.stdin.removeListener('data', onKeypress);
    process.stdout.removeListener('resize', render);
  }

  function onKeypress(key) {
    if (!running) return;
    const isSearchTab = activeTab === 4;

    // Ctrl+C always quits
    if (key === '\x03') {
      cleanup();
      return;
    }

    // Search tab: route printable keys to search input
    if (isSearchTab) {
      // Escape: clear search
      if (key === '\x1b' && key.length === 1) {
        searchQuery = '';
        searchResults = null;
        searchError = null;
        scrollOffset = 0;
        render();
        return;
      }

      // Enter: trigger search
      if (key === '\r' || key === '\n') {
        doSearch();
        return;
      }

      // Backspace / Delete
      if (key === '\x7f' || key === '\b') {
        if (searchQuery.length > 0) {
          searchQuery = searchQuery.slice(0, -1);
          render();
        }
        return;
      }

      // Tab: switch to next tab
      if (key === '\t') {
        activeTab = (activeTab + 1) % tabs.length;
        scrollOffset = 0;
        render();
        return;
      }

      // Arrow keys still navigate
      if (key === '\x1b[C') { activeTab = (activeTab + 1) % tabs.length; scrollOffset = 0; render(); return; }
      if (key === '\x1b[D') { activeTab = (activeTab - 1 + tabs.length) % tabs.length; scrollOffset = 0; render(); return; }
      if (key === '\x1b[A') { scrollOffset = Math.max(0, scrollOffset - 1); render(); return; }
      if (key === '\x1b[B') { scrollOffset++; render(); return; }

      // q quits only if search buffer is empty
      if (key === 'q' && searchQuery.length === 0) {
        cleanup();
        return;
      }

      // Printable ASCII → append to search query
      if (key.length === 1 && key.charCodeAt(0) >= 32 && key.charCodeAt(0) <= 126) {
        searchQuery += key;
        render();
        return;
      }
      return;
    }

    // Non-search tabs: normal keypress handling
    // q = quit
    if (key === 'q') {
      cleanup();
      return;
    }

    // Tab navigation
    if (key === '\x1b[C' || key === '\t') {
      activeTab = (activeTab + 1) % tabs.length;
      scrollOffset = 0;
      render();
      return;
    }
    if (key === '\x1b[D') {
      activeTab = (activeTab - 1 + tabs.length) % tabs.length;
      scrollOffset = 0;
      render();
      return;
    }

    // Number keys 1-5
    if (key >= '1' && key <= '5') {
      const idx = parseInt(key, 10) - 1;
      if (idx < tabs.length) { activeTab = idx; scrollOffset = 0; render(); }
      return;
    }

    // Overview tab: quick action navigation + launch
    if (activeTab === 0) {
      // ↑↓ / j/k move quick action cursor
      if (key === '\x1b[A' || key === 'k') {
        quickActionIdx = (quickActionIdx - 1 + QUICK_ACTIONS.length) % QUICK_ACTIONS.length;
        render();
        return;
      }
      if (key === '\x1b[B' || key === 'j') {
        quickActionIdx = (quickActionIdx + 1) % QUICK_ACTIONS.length;
        render();
        return;
      }
      // Enter: launch selected quick action
      if (key === '\r' || key === '\n') {
        pendingAction = QUICK_ACTIONS[quickActionIdx].cmd;
        cleanup();
        return;
      }
      // Letter shortcuts: a/v/r/c
      const qaMatch = QUICK_ACTIONS.find(qa => qa.key === key);
      if (qaMatch) {
        pendingAction = qaMatch.cmd;
        cleanup();
        return;
      }
      return;
    }

    // Other tabs: scroll
    if (key === '\x1b[A' || key === 'k') { scrollOffset = Math.max(0, scrollOffset - 1); render(); return; }
    if (key === '\x1b[B' || key === 'j') { scrollOffset++; render(); return; }
    if (key === '\x1b[5~') { scrollOffset = Math.max(0, scrollOffset - 10); render(); return; }
    if (key === '\x1b[6~') { scrollOffset += 10; render(); return; }
  }

  // Setup input
  process.stdin.setRawMode(true);
  process.stdin.resume();
  process.stdin.setEncoding('utf8');
  process.stdin.on('data', onKeypress);
  process.stdout.on('resize', render);

  // Graceful cleanup
  process.on('exit', cleanup);
  process.on('SIGINT', () => { cleanup(); process.exit(0); });
  process.on('SIGTERM', () => { cleanup(); process.exit(0); });

  // Initial render
  render();

  // Keep alive until user quits
  await new Promise(resolve => {
    const check = setInterval(() => {
      if (!running) { clearInterval(check); resolve(); }
    }, 100);
  });

  // Handle pending quick action after dashboard exits
  if (pendingAction) {
    const qa = QUICK_ACTIONS.find(q => q.cmd === pendingAction);
    const promptLabel = qa?.arg === '<pkg>' ? 'Package name' : 'URL to audit';
    console.log();
    const input = await askQuestion(`  ${c.cyan}${promptLabel}:${c.reset} `);
    if (!input) {
      console.log(`  ${c.dim}Cancelled.${c.reset}`);
      return;
    }
    console.log();
    // Build argv and re-enter main()
    const newArgs = ['node', 'cli.mjs'];
    switch (pendingAction) {
      case 'audit':
        newArgs.push('audit', input);
        break;
      case 'audit-verify':
        newArgs.push('audit', input, '--verify', 'self');
        break;
      case 'remote':
        newArgs.push('audit', input, '--remote');
        break;
      case 'consensus':
        newArgs.push('consensus', input);
        break;
    }
    process.argv = newArgs;
    await main();
  }
}

// ── Main ────────────────────────────────────────────────

async function main() {
  const rawArgs = process.argv.slice(2);
  
  // MCP server mode: launched by an editor (no TTY + no args) or explicit --stdio flag
  if (rawArgs.includes('--stdio') || (!process.stdin.isTTY && rawArgs.length === 0)) {
    await import('./index.mjs');
    return;
  }
  
  // Parse global flags early
  jsonMode = rawArgs.includes('--json');
  quietMode = rawArgs.includes('--quiet') || rawArgs.includes('-q');
  // --no-color already handled at top level for `c` object

  // Strip global flags from args (including --model <value>, --format <value>)
  const globalFlags = new Set(['--json', '--quiet', '-q', '--no-color', '--no-upload', '--remote']);
  let args = rawArgs.filter(a => !globalFlags.has(a));
  // Remove --model <value> and --models <value> pairs
  const modelIdx = args.indexOf('--model');
  if (modelIdx !== -1) args.splice(modelIdx, 2);
  const modelsIdx = args.indexOf('--models');
  if (modelsIdx !== -1) args.splice(modelsIdx, 2);
  // Remove --format <value> pair
  const formatIdx = args.indexOf('--format');
  const formatFlag = formatIdx !== -1 ? args.splice(formatIdx, 2)[1] : null;
  // --json is alias for --format json
  const outputFormat = formatFlag || (jsonMode ? 'json' : null);
  // Validate --format value
  if (outputFormat && !['json', 'sarif'].includes(outputFormat)) {
    console.error(`  ${c.red}Unknown format: ${outputFormat}${c.reset}`);
    console.error(`  ${c.dim}Supported formats: json, sarif${c.reset}`);
    process.exitCode = 2; return;
  }
  // SARIF mode: suppress console output so only clean JSON goes to stdout
  if (outputFormat === 'sarif') { quietMode = true; jsonMode = true; }

  // --remote: use server-side scan instead of local LLM
  const remoteFlag = rawArgs.includes('--remote');

  // Detect per-command --help BEFORE stripping (e.g. `agentaudit model --help`)
  const wantsHelp = args.includes('--help') || args.includes('-h');
  // Strip --help/-h from args for routing
  args = args.filter(a => a !== '--help' && a !== '-h');

  if (args[0] === '-v' || args[0] === '--version') {
    console.log(`agentaudit ${getVersion()}`);
    process.exitCode = 0; return;
  }

  // Subcommand help definitions
  const subcommandHelp = {
    discover: [
      `${c.bold}agentaudit discover${c.reset} [options]`,
      ``,
      `Find MCP servers across 15+ AI tools (Claude Desktop, Claude Code, Cursor, VS Code,`,
      `Windsurf, Cline, Roo Code, Amazon Q, Gemini CLI, Zed, Continue.dev, Goose, Codex CLI).`,
      `Checks global + project-level configs on macOS, Windows, and Linux.`,
      ``,
      `${c.bold}Options:${c.reset}`,
      `  --quick, -s    Auto-scan all discovered servers (regex-based)`,
      `  --deep, -a     Interactively select servers for deep LLM audit`,
      ``,
      `${c.bold}Examples:${c.reset}`,
      `  agentaudit discover`,
      `  agentaudit discover --quick`,
      `  agentaudit discover --deep`,
    ],
    scan: [
      `${c.bold}agentaudit scan${c.reset} <url> [url...] [options]`,
      ``,
      `Quick regex-based static security scan (~2s). Checks for 15+ patterns`,
      `(command injection, eval, hardcoded secrets, path traversal, etc.)`,
      ``,
      `${c.bold}Options:${c.reset}`,
      `  --deep             Run deep LLM audit instead (same as \`agentaudit audit\`)`,
      `  --remote           Use agentaudit.dev server for --deep (no LLM key needed)`,
      `  --format sarif      Output results as SARIF 2.1.0 (for GitHub Code Scanning)`,
      ``,
      `${c.bold}Examples:${c.reset}`,
      `  agentaudit scan https://github.com/owner/repo`,
      `  agentaudit scan https://github.com/a/b https://github.com/c/d`,
      `  agentaudit scan https://github.com/owner/repo --deep`,
      `  agentaudit scan https://github.com/owner/repo --deep --remote`,
      `  agentaudit scan https://github.com/owner/repo --format sarif > results.sarif`,
    ],
    audit: [
      `${c.bold}agentaudit audit${c.reset} <url> [url...] [options]`,
      ``,
      `Deep LLM-powered security audit with optional verification pass.`,
      ``,
      `${c.bold}Options:${c.reset}`,
      `  --verify [mode]    Enable Pass 2 verification (reduces false positives)`,
      `                       self   — same model verifies its own findings (default)`,
      `                       cross  — different model verifies (higher quality)`,
      `                       <name> — specific model as verifier (e.g. sonnet)`,
      `  --no-verify        Disable verification (even if default)`,
      `  --remote           Use agentaudit.dev server (no LLM key needed, 3/day free)`,
      `  --model <name>     Override LLM model for this run`,
      `  --models <a,b,c>   Multi-model audit (parallel calls, consensus comparison)`,
      `  --no-upload        Skip uploading report to registry`,
      `  --export           Export audit payload as markdown (for manual LLM review)`,
      `  --format sarif      Output results as SARIF 2.1.0 (for GitHub Code Scanning)`,
      `  --debug            Show raw LLM response on parse errors`,
      ``,
      `${c.bold}Examples:${c.reset}`,
      `  agentaudit audit https://github.com/owner/repo`,
      `  agentaudit audit https://github.com/owner/repo --verify`,
      `  agentaudit audit https://github.com/owner/repo --verify cross`,
      `  agentaudit audit https://github.com/owner/repo --remote`,
      `  agentaudit audit https://github.com/owner/repo --model gpt-4o`,
      `  agentaudit audit https://github.com/owner/repo --models opus,sonnet,grok-4,gemini-3.1-pro`,
      `  agentaudit audit https://github.com/owner/repo --format sarif > results.sarif`,
      `  agentaudit audit https://github.com/owner/repo --export`,
    ],
    lookup: [
      `${c.bold}agentaudit lookup${c.reset} <name> [options]`,
      ``,
      `Look up a package in the AgentAudit registry. Shows trust score,`,
      `findings, confidence level, and audit history.`,
      ``,
      `${c.bold}Aliases:${c.reset} lookup, check`,
      ``,
      `${c.bold}Examples:${c.reset}`,
      `  agentaudit lookup fastmcp`,
      `  agentaudit lookup @anthropic/mcp-server-filesystem --json`,
      `  agentaudit check fastmcp`,
    ],
    check: null, // alias → lookup
    model: [
      `${c.bold}agentaudit model${c.reset} [name|reset]`,
      ``,
      `Configure LLM provider and model. Interactive two-step menu when`,
      `called without arguments: choose provider, then choose model.`,
      ``,
      `${c.bold}Usage:${c.reset}`,
      `  agentaudit model              Interactive provider + model menu`,
      `  agentaudit model <name>       Set model directly (keeps current provider)`,
      `  agentaudit model reset        Reset provider + model to defaults`,
      ``,
      `${c.bold}Examples:${c.reset}`,
      `  agentaudit model`,
      `  agentaudit model gpt-4o`,
      `  agentaudit model qwen/qwen3-coder`,
      `  agentaudit model reset`,
    ],
    setup: [
      `${c.bold}agentaudit setup${c.reset}`,
      ``,
      `Log in to agentaudit.dev — create an account or enter an existing API key.`,
      `This enables uploading audit reports to the public registry.`,
      ``,
      `${c.bold}Note:${c.reset} This is NOT for LLM/provider configuration. Use ${c.cyan}agentaudit model${c.reset} for that.`,
      ``,
      `${c.bold}Examples:${c.reset}`,
      `  agentaudit setup`,
    ],
    status: [
      `${c.bold}agentaudit status${c.reset}`,
      ``,
      `Show current configuration: active LLM provider, model, account`,
      `status, and which API keys are available.`,
      ``,
      `${c.bold}Aliases:${c.reset} status, whoami`,
      ``,
      `${c.bold}Examples:${c.reset}`,
      `  agentaudit status`,
      `  agentaudit status --json`,
    ],
    dashboard: [
      `${c.bold}agentaudit dashboard${c.reset}`,
      ``,
      `Interactive full-screen dashboard with stats, leaderboard, and benchmark.`,
      `Uses alternate screen buffer — your scrollback stays intact.`,
      ``,
      `${c.bold}Navigation:${c.reset}`,
      `  \u2190\u2192 / Tab      Switch between tabs`,
      `  1-5            Jump to tab by number`,
      `  \u2191\u2193 / j/k       Scroll content`,
      `  PgUp/PgDn     Scroll fast`,
      `  q / Ctrl+C    Quit`,
      ``,
      `${c.bold}Tabs:${c.reset}`,
      `  [1] Overview    Your profile + registry stats`,
      `  [2] Leaderboard Top contributors ranking`,
      `  [3] Benchmark   LLM model performance comparison`,
      `  [4] Activity    Your recent audits & findings`,
      `  [5] Search      Search packages (interactive input)`,
      ``,
      `${c.bold}Aliases:${c.reset} dashboard, dash`,
    ],
    dash: null, // alias → dashboard
    leaderboard: [
      `${c.bold}agentaudit leaderboard${c.reset} [options]`,
      ``,
      `Show top contributors ranking. Pipe-friendly output (no alt-screen).`,
      ``,
      `${c.bold}Options:${c.reset}`,
      `  --tab <name>   Category: overall (default), monthly, reviewers, verifiers, streaks`,
      `  --all           Show all entries (default: top 20)`,
      `  --json          Machine-readable JSON output`,
      ``,
      `${c.bold}Aliases:${c.reset} leaderboard, lb`,
      ``,
      `${c.bold}Examples:${c.reset}`,
      `  agentaudit leaderboard`,
      `  agentaudit leaderboard --tab monthly`,
      `  agentaudit leaderboard --all --json`,
    ],
    lb: null, // alias → leaderboard
    benchmark: [
      `${c.bold}agentaudit benchmark${c.reset} [options]`,
      ``,
      `Compare LLM model performance across security audits.`,
      `Shows detection rates, severity breakdown, and vulnerability landscape.`,
      ``,
      `${c.bold}Options:${c.reset}`,
      `  --json          Machine-readable JSON output`,
      ``,
      `${c.bold}Aliases:${c.reset} benchmark, bench`,
      ``,
      `${c.bold}Examples:${c.reset}`,
      `  agentaudit benchmark`,
      `  agentaudit benchmark --json`,
    ],
    bench: null, // alias → benchmark
    consensus: [
      `${c.bold}agentaudit consensus${c.reset} <package-name>`,
      ``,
      `View multi-model consensus status from the AgentAudit registry.`,
      `Shows agreement across different LLM models and peer reviewers.`,
      ``,
      `${c.bold}Options:${c.reset}`,
      `  --json          Machine-readable JSON output`,
      ``,
      `${c.bold}Examples:${c.reset}`,
      `  agentaudit consensus nanobanana-mcp-server`,
      `  agentaudit consensus fastmcp --json`,
    ],
    history: [
      `${c.bold}agentaudit history${c.reset} [show|upload] [n]`,
      ``,
      `Show your local audit history. Results are stored in ~/.config/agentaudit/history/`,
      `after every audit run. No internet connection required.`,
      ``,
      `${c.bold}Subcommands:${c.reset}`,
      `  history              List all local audits (numbered)`,
      `  history show <n>     Show full report details for entry #n`,
      `  history upload <n>   Retry upload of entry #n to agentaudit.dev`,
      ``,
      `${c.bold}Options:${c.reset}`,
      `  --json          Machine-readable JSON output`,
      ``,
      `${c.bold}Examples:${c.reset}`,
      `  agentaudit history`,
      `  agentaudit history show 1`,
      `  agentaudit history upload 1`,
    ],
    activity: [
      `${c.bold}agentaudit activity${c.reset} [options]`,
      ``,
      `Show your recent audits and findings from the AgentAudit registry (online).`,
      `Requires being logged in (run ${c.cyan}agentaudit setup${c.reset} first).`,
      ``,
      `${c.bold}Options:${c.reset}`,
      `  --json          Machine-readable JSON output`,
      ``,
      `${c.bold}Aliases:${c.reset} activity, my`,
      ``,
      `${c.bold}Examples:${c.reset}`,
      `  agentaudit activity`,
      `  agentaudit activity --json`,
      `  agentaudit my`,
    ],
    my: null, // alias → activity
    search: [
      `${c.bold}agentaudit search${c.reset} <query> [options]`,
      ``,
      `Search for packages in the AgentAudit registry by name, ASF-ID, or hash.`,
      ``,
      `${c.bold}Options:${c.reset}`,
      `  --json          Machine-readable JSON output`,
      ``,
      `${c.bold}Aliases:${c.reset} search, find`,
      ``,
      `${c.bold}Examples:${c.reset}`,
      `  agentaudit search fastmcp`,
      `  agentaudit search mcp-server`,
      `  agentaudit search ASF-2025-0001`,
      `  agentaudit search fastmcp --json`,
      `  agentaudit find fastmcp`,
    ],
    find: null, // alias → search
    profile: [
      `${c.bold}agentaudit profile${c.reset}`,
      ``,
      `Show your AgentAudit profile — rank, points, audit stats,`,
      `and a link to your public profile on agentaudit.dev.`,
      ``,
      `Requires being logged in (run ${c.cyan}agentaudit setup${c.reset} first).`,
      ``,
      `${c.bold}Options:${c.reset}`,
      `  --json          Machine-readable JSON output`,
      ``,
      `${c.bold}Examples:${c.reset}`,
      `  agentaudit profile`,
      `  agentaudit profile --json`,
    ],
  };

  // Show subcommand help: `agentaudit help <cmd>` or `agentaudit <cmd> --help`
  function showSubcommandHelp(cmd) {
    let helpLines = subcommandHelp[cmd];
    if (helpLines === null) {
      // alias redirect
      const aliases = { check: 'lookup', dash: 'dashboard', lb: 'leaderboard', bench: 'benchmark', my: 'activity', find: 'search' };
      helpLines = subcommandHelp[aliases[cmd] || cmd];
    }
    if (!helpLines) {
      console.log(`  ${c.red}No help available for "${cmd}"${c.reset}`);
      console.log(`  ${c.dim}Run ${c.cyan}agentaudit help${c.dim} for available commands${c.reset}`);
      return;
    }
    banner();
    for (const line of helpLines) console.log(`  ${line}`);
    console.log();
  }

  // Handle: `agentaudit <cmd> --help` (wantsHelp + has a command)
  if (wantsHelp && args[0] && args[0] !== '--help' && args[0] !== '-h') {
    const cmd = args[0];
    if (subcommandHelp[cmd] !== undefined) {
      showSubcommandHelp(cmd);
      process.exitCode = 0; return;
    }
  }

  // Handle: `agentaudit help [cmd]`
  if (args[0] === 'help') {
    const helpCmd = args[1];
    if (helpCmd && subcommandHelp[helpCmd] !== undefined) {
      showSubcommandHelp(helpCmd);
      process.exitCode = 0; return;
    }
    // No subcommand or unknown → show main help
    wantsHelp || (args[0] = '--help'); // fall through to main help
  }

  if (args[0] === '--help' || args[0] === '-h' || args[0] === 'help' || (wantsHelp && args.length === 0)) {
    banner();
    console.log(`  ${c.bold}USAGE${c.reset}`);
    console.log(`    agentaudit <command> [options]`);
    console.log();
    console.log(`  ${c.bold}SCAN & AUDIT${c.reset}`);
    console.log(`    ${c.cyan}discover${c.reset}              Find MCP servers & skills in your AI tools`);
    console.log(`    ${c.cyan}scan${c.reset} <url> [url...]   Quick static scan (regex, ~2s)`);
    console.log(`    ${c.cyan}audit${c.reset} <url> [url...]  Deep LLM-powered security audit (~30s)`);
    console.log(`    ${c.cyan}validate${c.reset} [path]       Validate SKILL.md format & security`);
    console.log(`    ${c.cyan}lookup${c.reset} <name>         Look up package in registry`);
    console.log(`    ${c.cyan}consensus${c.reset} <name>      View multi-model consensus for a package`);
    console.log();
    console.log(`  ${c.bold}COMMUNITY${c.reset}`);
    console.log(`    ${c.cyan}dashboard${c.reset}             Interactive dashboard (full-screen)`);
    console.log(`    ${c.cyan}leaderboard${c.reset}           Top contributors ranking`);
    console.log(`    ${c.cyan}benchmark${c.reset}             LLM model performance comparison`);
    console.log(`    ${c.cyan}history${c.reset}               Your local audit history`);
    console.log(`    ${c.cyan}activity${c.reset}              Your recent audits & findings (online)`);
    console.log(`    ${c.cyan}search${c.reset} <query>        Search packages in registry`);
    console.log();
    console.log(`  ${c.bold}CONFIGURATION${c.reset}`);
    console.log(`    ${c.cyan}model${c.reset}                 Configure LLM provider + model`);
    console.log(`    ${c.cyan}login${c.reset}                 Sign in with GitHub (opens browser)`);
    console.log(`    ${c.cyan}setup${c.reset}                 Manual login — paste API key`);
    console.log(`    ${c.cyan}status${c.reset}                Show current config + auth status`);
    console.log(`    ${c.cyan}profile${c.reset}               Your profile — rank, points, audit stats`);
    console.log();
    console.log(`  ${c.bold}FLAGS${c.reset}`);
    console.log(`    ${c.dim}--json             Machine-readable JSON output${c.reset}`);
    console.log(`    ${c.dim}--quiet            Suppress banner${c.reset}`);
    console.log(`    ${c.dim}--no-color         Disable ANSI colors (also: NO_COLOR env)${c.reset}`);
    console.log(`    ${c.dim}--verify [mode]    Verify findings (reduces false positives)${c.reset}`);
    console.log(`    ${c.dim}--model <name>     Override LLM model for this run${c.reset}`);
    console.log(`    ${c.dim}--models <a,b,c>   Multi-model audit (parallel, with consensus)${c.reset}`);
    console.log(`    ${c.dim}--no-upload        Skip uploading report to registry${c.reset}`);
    console.log(`    ${c.dim}--export           Export audit payload as markdown${c.reset}`);
    console.log(`    ${c.dim}--debug            Show raw LLM response on parse errors${c.reset}`);
    console.log();
    console.log(`  ${c.bold}EXAMPLES${c.reset}`);
    console.log(`    agentaudit discover --quick`);
    console.log(`    agentaudit scan https://github.com/owner/repo`);
    console.log(`    agentaudit audit https://github.com/owner/repo`);
    console.log(`    agentaudit audit <url> --models opus,sonnet,grok-4,gemini-3.1-pro`);
    console.log(`    agentaudit lookup fastmcp --json`);
    console.log();
    console.log(`  ${c.bold}LEARN MORE${c.reset}`);
    console.log(`    ${c.dim}agentaudit help <command>${c.reset}     Help for a specific command`);
    console.log(`    ${c.dim}https://agentaudit.dev${c.reset}        Documentation`);
    console.log();
    process.exitCode = 0; return;
  }
  
  // Default no-arg → discover
  const command = args.length === 0 ? 'discover' : args[0];
  const targets = args.slice(1);

  // Dashboard/Leaderboard/Benchmark — before banner() since dashboard uses alt-screen
  if (command === 'dashboard' || command === 'dash') {
    await dashboardCommand();
    return;
  }
  if (command === 'leaderboard' || command === 'lb') {
    await leaderboardCommand(targets);
    return;
  }
  if (command === 'benchmark' || command === 'bench') {
    await benchmarkCommand(targets);
    return;
  }
  if (command === 'history') {
    banner();
    const subCmd = targets[0];
    const entries = loadHistory(30);

    if (entries.length === 0 && !subCmd) {
      console.log(`  ${c.dim}No local audit history yet. Run ${c.cyan}agentaudit audit <url>${c.dim} to start.${c.reset}`);
      console.log();
      return;
    }

    // history show <n> — show full report details
    if (subCmd === 'show') {
      const idx = parseInt(targets[1], 10) - 1;
      if (isNaN(idx) || idx < 0 || idx >= entries.length) {
        console.log(`  ${c.red}Invalid index.${c.reset} Use a number from 1 to ${entries.length}.`);
        console.log(`  ${c.dim}Run ${c.cyan}agentaudit history${c.dim} to see the list.${c.reset}`);
        return;
      }
      const entry = entries[idx];
      if (jsonMode) {
        console.log(JSON.stringify(entry, null, 2));
        return;
      }
      console.log(sectionHeader(`Report: ${entry.skill_slug || 'unknown'}`));
      console.log();
      console.log(`  Source      ${c.bold}${entry.source_url || '?'}${c.reset}`);
      console.log(`  Model       ${c.bold}${entry.audit_model || '?'}${c.reset}  ${c.dim}(${entry.audit_provider || '?'})${c.reset}`);
      console.log(`  Risk        ${riskBadge(entry.risk_score ?? 0)}`);
      console.log(`  Result      ${entry.result || '?'}`);
      console.log(`  Files       ${entry.files_scanned || '?'}  ${c.dim}Duration: ${entry.audit_duration_ms ? (entry.audit_duration_ms / 1000).toFixed(1) + 's' : '?'}${c.reset}`);
      console.log(`  Tokens      ${c.dim}in: ${entry.input_tokens || '?'}  out: ${entry.output_tokens || '?'}${c.reset}`);
      console.log(`  File        ${c.dim}${entry._file}${c.reset}`);
      console.log();
      if (entry.findings && entry.findings.length > 0) {
        console.log(sectionHeader(`Findings (${entry.findings.length})`));
        console.log();
        for (const f of entry.findings) {
          const sc = severityColor(f.severity);
          console.log(`  ${sc}┃${c.reset} ${sc}${(f.severity || '').toUpperCase().padEnd(8)}${c.reset}  ${c.bold}${f.title}${c.reset}`);
          if (f.file) console.log(`  ${sc}┃${c.reset}           ${c.dim}${f.file}${f.line ? ':' + f.line : ''}${c.reset}`);
          if (f.description) console.log(`  ${sc}┃${c.reset}           ${c.dim}${f.description.slice(0, 200)}${c.reset}`);
          console.log();
        }
      } else {
        console.log(`  ${c.green}No findings.${c.reset}`);
        console.log();
      }
      return;
    }

    // history upload <n> — retry upload of a local report
    if (subCmd === 'upload') {
      const idx = parseInt(targets[1], 10) - 1;
      if (isNaN(idx) || idx < 0 || idx >= entries.length) {
        console.log(`  ${c.red}Invalid index.${c.reset} Use a number from 1 to ${entries.length}.`);
        console.log(`  ${c.dim}Run ${c.cyan}agentaudit history${c.dim} to see the list.${c.reset}`);
        return;
      }
      const entry = entries[idx];
      const creds = loadCredentials();
      if (!creds) {
        console.log(`  ${c.red}Not logged in.${c.reset} Run ${c.cyan}agentaudit login${c.reset} first.`);
        return;
      }
      process.stdout.write(`  Uploading ${c.bold}${entry.skill_slug}${c.reset} (${entry.audit_model || '?'})...`);
      try {
        const reportCopy = { ...entry };
        delete reportCopy._file;
        const res = await fetch(`${REGISTRY_URL}/api/reports`, {
          method: 'POST',
          headers: { 'Authorization': `Bearer ${creds.api_key}`, 'Content-Type': 'application/json' },
          body: JSON.stringify(reportCopy),
          signal: AbortSignal.timeout(30_000),
        });
        if (res.ok) {
          const data = await res.json();
          console.log(` ${c.green}done${c.reset} ${c.dim}(report #${data.report_id})${c.reset}`);
          console.log(`  ${c.dim}${REGISTRY_URL}/packages/${entry.skill_slug}${c.reset}`);
        } else {
          const errBody = await res.text().catch(() => '');
          console.log(` ${c.red}failed (HTTP ${res.status})${c.reset}`);
          if (errBody) console.log(`  ${c.dim}${errBody.slice(0, 300)}${c.reset}`);
        }
      } catch (e) {
        console.log(` ${c.red}failed: ${e.message}${c.reset}`);
      }
      console.log();
      return;
    }

    // Default: list all entries
    if (jsonMode) {
      console.log(JSON.stringify(entries, null, 2));
      return;
    }

    console.log(sectionHeader(`Local History (${entries.length})`));
    console.log();

    for (let i = 0; i < entries.length; i++) {
      const entry = entries[i];
      const slug = entry.skill_slug || 'unknown';
      const risk = entry.risk_score ?? '?';
      const sev = entry.max_severity || 'none';
      const sc = severityColor(sev);
      const model = entry.audit_model || '?';
      const fc = entry.findings?.length || 0;
      const ts = entry._file?.slice(0, 10) || '';
      const num = `${c.dim}${String(i + 1).padStart(2)}.${c.reset}`;
      console.log(`  ${num} ${sc}┃${c.reset} ${c.bold}${slug.padEnd(30)}${c.reset} ${riskBadge(risk)}  ${c.dim}${model}${c.reset}`);
      console.log(`     ${sc}┃${c.reset} ${c.dim}${ts}  ${fc} findings  ${sev.toUpperCase()}${c.reset}`);
      console.log();
    }
    console.log(`  ${c.dim}Tip: ${c.cyan}agentaudit history show <n>${c.dim} for details, ${c.cyan}history upload <n>${c.dim} to retry upload${c.reset}`);
    console.log();
    return;
  }
  if (command === 'activity' || command === 'my') {
    await activityCommand(targets);
    return;
  }
  if (command === 'search' || command === 'find') {
    await searchCommand(targets);
    return;
  }
  if (command === 'consensus') {
    banner();
    const pkg = targets[0];
    if (!pkg) {
      console.log(`  ${c.red}Error: package name required${c.reset}`);
      console.log(`  ${c.dim}Usage: ${c.cyan}agentaudit consensus <package-name>${c.reset}`);
      process.exitCode = 2;
      return;
    }
    const slug = pkg.toLowerCase().replace(/[^a-z0-9-]/g, '-');
    if (!jsonMode) console.log(`  Fetching consensus for ${c.bold}${slug}${c.reset}...`);
    try {
      const res = await fetch(`${REGISTRY_URL}/api/packages/${slug}/consensus`, { signal: AbortSignal.timeout(10_000) });
      if (!res.ok) {
        if (res.status === 404) {
          console.log(`  ${c.yellow}Not found${c.reset} — "${slug}" hasn't been audited yet.`);
          console.log(`  ${c.dim}Run: ${c.cyan}agentaudit audit <repo-url>${c.dim} to create the first audit${c.reset}`);
        } else {
          console.log(`  ${c.red}API error (HTTP ${res.status})${c.reset}`);
        }
        // Suggest similar packages via search
        await suggestSimilarPackages(slug);
        return;
      }
      const data = await res.json();

      // Check if package actually has any reports
      if ((!data.total_reports && data.total_reports !== undefined) || (data.total_reports === 0 && (!data.findings || data.findings.length === 0))) {
        if (jsonMode) { console.log(JSON.stringify(data, null, 2)); return; }
        console.log(`  ${c.yellow}No reports found${c.reset} — "${slug}" hasn't been audited yet.`);
        console.log(`  ${c.dim}Run: ${c.cyan}agentaudit audit <repo-url>${c.dim} to create the first audit${c.reset}`);
        // Suggest similar packages
        await suggestSimilarPackages(slug);
        return;
      }

      if (jsonMode) { console.log(JSON.stringify(data, null, 2)); return; }

      console.log();
      console.log(sectionHeader(`Consensus: ${slug}`));
      console.log();

      // Status
      const status = data.consensus_status || data.status || 'pending';
      const statusColor = status === 'reached' ? c.green : status === 'disputed' ? c.yellow : c.dim;
      console.log(`  Status:   ${statusColor}${status.toUpperCase()}${c.reset}`);

      // Risk + Severity
      if (data.consensus_risk_score != null) console.log(`  Risk:     ${riskBadge(data.consensus_risk_score)}`);
      if (data.consensus_severity) {
        const sc = severityColor(data.consensus_severity);
        console.log(`  Severity: ${sc}${data.consensus_severity.toUpperCase()}${c.reset}`);
      }

      // Models
      if (data.models && data.models.length > 0) {
        console.log();
        console.log(`  ${c.bold}Models (${data.models.length}):${c.reset}`);
        for (const m of data.models) {
          const sc = severityColor(m.severity || m.max_severity);
          const risk = m.risk_score ?? '?';
          console.log(`    ${sc}┃${c.reset} ${(m.model || m.audit_model || '?').padEnd(30)} ${c.dim}risk ${risk}${c.reset}  ${sc}${(m.severity || m.max_severity || '').toUpperCase()}${c.reset}`);
        }
      }

      // Reviewers
      if (data.reviews != null || data.reviewer_count != null) {
        const count = data.reviewer_count || data.reviews?.length || 0;
        console.log();
        console.log(`  ${c.dim}Reviews: ${count}  |  Threshold: 5 reviewers, >60% agreement${c.reset}`);
      }

      console.log();
      console.log(`  ${c.dim}Full details: ${REGISTRY_URL}/packages/${slug}${c.reset}`);
      console.log();
    } catch (err) {
      console.log(`  ${c.red}Failed: ${err.message}${c.reset}`);
    }
    return;
  }

  banner();

  if (command === 'setup' || command === 'login') {
    await setupCommand();
    return;
  }

  if (command === 'status' || command === 'whoami') {
    // ── Status / diagnostic overview ──
    const config = loadLlmConfig();
    const creds = loadCredentials();
    const resolved = resolveProvider();

    console.log(`  ${c.bold}Status${c.reset}`);
    console.log();

    // Provider + Model
    const prefProvider = config?.preferred_provider;
    const prefModel = config?.llm_model;
    if (prefProvider && resolved) {
      console.log(`  Provider    ${c.bold}${resolved.name}${c.reset}  ${c.dim}(${resolved.key})${c.reset}  ${c.green}✔${c.reset}`);
    } else if (resolved) {
      console.log(`  Provider    ${c.bold}${resolved.name}${c.reset}  ${c.dim}(auto-detected via ${resolved.key})${c.reset}  ${c.green}✔${c.reset}`);
    } else {
      console.log(`  Provider    ${c.yellow}none${c.reset}  ${c.dim}— set an API key or run ${c.cyan}agentaudit model${c.dim}${c.reset}`);
    }

    if (prefModel) {
      console.log(`  Model       ${c.bold}${prefModel}${c.reset}  ${c.dim}(custom)${c.reset}`);
    } else if (resolved) {
      console.log(`  Model       ${c.dim}${resolved.model} (provider default)${c.reset}`);
    } else {
      console.log(`  Model       ${c.dim}—${c.reset}`);
    }
    console.log();

    // Account / auth
    if (creds) {
      console.log(`  Account     ${c.bold}${creds.agent_name}${c.reset}  ${c.green}✔ logged in${c.reset}`);
      console.log(`  ${c.dim}            Key: ${creds.api_key.slice(0, 12)}...${c.reset}`);
      // Remote scan quota
      try {
        const quotaRes = await fetch(`${REGISTRY_URL}/api/scan`, {
          headers: { 'Authorization': `Bearer ${creds.api_key}` },
          signal: AbortSignal.timeout(5_000),
        });
        if (quotaRes.ok) {
          const quota = await quotaRes.json();
          const resetLabel = quota.resets_in_ms
            ? ` ${c.dim}(resets in ${Math.ceil(quota.resets_in_ms / 3600000)}h)${c.reset}`
            : '';
          console.log(`  Remote      ${c.bold}${quota.remaining}${c.reset} of ${quota.limit} free scans remaining${resetLabel}`);
        }
      } catch {}
    } else {
      console.log(`  Account     ${c.yellow}not configured${c.reset}  ${c.dim}— run ${c.cyan}agentaudit setup${c.dim} to create one${c.reset}`);
    }
    console.log();

    // All provider keys
    const seen = new Set();
    const keyLines = [];
    for (const p of LLM_PROVIDERS) {
      if (seen.has(p.provider)) continue;
      seen.add(p.provider);
      const keys = LLM_PROVIDERS.filter(x => x.provider === p.provider);
      const hasKey = keys.some(x => process.env[x.key]);
      keyLines.push({ name: p.name, key: p.key, hasKey });
    }
    console.log(`  ${c.bold}API Keys${c.reset}`);
    for (const k of keyLines) {
      const icon = k.hasKey ? `${c.green}✔${c.reset}` : `${c.dim}✗${c.reset}`;
      const label = k.hasKey ? k.name : `${c.dim}${k.name}${c.reset}`;
      console.log(`    ${icon}  ${label}  ${c.dim}${k.key}${c.reset}`);
    }
    console.log();

    // Personal stats (from registry, silently skip on error)
    if (creds?.agent_name && creds.agent_name !== 'env') {
      try {
        const [agentRes, lbRes] = await Promise.all([
          fetch(`${REGISTRY_URL}/api/agents/${encodeURIComponent(creds.agent_name)}`, {
            headers: { 'Authorization': `Bearer ${creds.api_key}` },
            signal: AbortSignal.timeout(10_000),
          }).then(r => r.ok ? r.json() : null),
          fetch(`${REGISTRY_URL}/api/leaderboard?limit=100`, { signal: AbortSignal.timeout(10_000) }).then(r => r.ok ? r.json() : null),
        ]);
        if (agentRes) {
          let rank = null;
          if (Array.isArray(lbRes)) {
            const idx = lbRes.findIndex(e => e.agent_name === creds.agent_name);
            if (idx >= 0) rank = idx + 1;
          }
          // Update profile cache
          saveProfileCache({
            agent_name: creds.agent_name,
            rank,
            total_points: agentRes.total_points || 0,
            total_reports: agentRes.total_reports || 0,
          });
          console.log(`  ${c.bold}Profile${c.reset}`);
          console.log(`    Rank        ${c.bold}${rank ? `#${rank} of ${lbRes.length}` : '-'}${c.reset}`);
          console.log(`    Points      ${c.bold}${fmtNum(agentRes.total_points || 0)}${c.reset}`);
          console.log(`    Audits      ${c.bold}${fmtNum(agentRes.total_reports || 0)}${c.reset}`);
          console.log(`    Findings    ${c.bold}${fmtNum(agentRes.total_findings_submitted || 0)}${c.reset} ${c.dim}(${fmtNum(agentRes.total_findings_confirmed || 0)} confirmed)${c.reset}`);
          console.log();
        }
      } catch {}
    }

    // JSON mode
    if (jsonMode) {
      const status = {
        version: getVersion(),
        provider: resolved ? { name: resolved.name, provider: resolved.provider, key: resolved.key, model: prefModel || resolved.model } : null,
        account: creds ? { agent_name: creds.agent_name, has_key: true } : null,
        api_keys: keyLines.reduce((acc, k) => { acc[k.key] = k.hasKey; return acc; }, {}),
      };
      console.log(JSON.stringify(status, null, 2));
    }
    return;
  }

  if (command === 'profile') {
    const creds = loadCredentials();
    if (!creds) {
      console.log(`  ${c.yellow}Not logged in.${c.reset}`);
      console.log(`  ${c.dim}Run ${c.cyan}agentaudit setup${c.dim} to link your API key.${c.reset}`);
      console.log();
      return;
    }

    const agentName = creds.agent_name || 'unknown';
    console.log(`  ${c.bold}Profile${c.reset}  ${c.cyan}${agentName}${c.reset}`);
    console.log();

    try {
      process.stdout.write(`  ${c.dim}Fetching profile data...${c.reset}`);
      const [agentRes, lbRes] = await Promise.all([
        fetch(`${REGISTRY_URL}/api/agents/${encodeURIComponent(agentName)}`, {
          headers: { 'Authorization': `Bearer ${creds.api_key}` },
          signal: AbortSignal.timeout(10_000),
        }).then(r => r.ok ? r.json() : null),
        fetch(`${REGISTRY_URL}/api/leaderboard?limit=100`, {
          signal: AbortSignal.timeout(10_000),
        }).then(r => r.ok ? r.json() : null),
      ]);
      process.stdout.write('\r\x1b[K');

      if (!agentRes) {
        console.log(`  ${c.yellow}Could not fetch profile data.${c.reset}`);
        console.log(`  ${c.dim}Your account may not have submitted any audits yet.${c.reset}`);
        console.log();
        console.log(`  ${c.dim}Web profile: ${c.cyan}${REGISTRY_URL}/profile${c.reset}`);
        console.log();
        return;
      }

      let rank = null;
      if (Array.isArray(lbRes)) {
        const idx = lbRes.findIndex(e => e.agent_name === agentName);
        if (idx >= 0) rank = idx + 1;
      }

      // Update cache
      saveProfileCache({
        agent_name: agentName,
        rank,
        total_points: agentRes.total_points || 0,
        total_reports: agentRes.total_reports || 0,
      });

      if (jsonMode) {
        console.log(JSON.stringify({
          agent_name: agentName,
          rank: rank ? { position: rank, total: lbRes?.length || 0 } : null,
          total_points: agentRes.total_points || 0,
          total_reports: agentRes.total_reports || 0,
          total_findings_submitted: agentRes.total_findings_submitted || 0,
          total_findings_confirmed: agentRes.total_findings_confirmed || 0,
          profile_url: `${REGISTRY_URL}/profile`,
        }, null, 2));
        return;
      }

      const boxW = 44;
      const rankStr = rank ? `#${rank} of ${lbRes.length}` : '—';
      const pts = agentRes.total_points || 0;
      const audits = agentRes.total_reports || 0;
      const findingsSubmitted = agentRes.total_findings_submitted || 0;
      const findingsConfirmed = agentRes.total_findings_confirmed || 0;
      const ptsBar = renderBar(pts, Math.max(pts, 1000), boxW - 16);

      const contentLines = [
        '',
        `${c.bold}${c.cyan}${agentName}${c.reset}${' '.repeat(Math.max(1, boxW - 6 - agentName.length - rankStr.length))}${c.bold}${rankStr}${c.reset}`,
        '',
        `Points      ${c.bold}${padLeft(fmtNum(pts), 8)}${c.reset}`,
        `Audits      ${c.bold}${padLeft(fmtNum(audits), 8)}${c.reset}`,
        `Findings    ${c.bold}${padLeft(fmtNum(findingsSubmitted), 8)}${c.reset}  ${c.dim}(${fmtNum(findingsConfirmed)} confirmed)${c.reset}`,
        '',
        ptsBar,
        '',
        `${c.dim}${REGISTRY_URL}/profile${c.reset}`,
        `${c.dim}Key: ${creds.api_key.slice(0, 12)}...${c.reset}`,
        '',
      ];
      const boxLines = drawBox('Profile', contentLines, boxW + 4);
      for (const line of boxLines) console.log(line);
      console.log();
    } catch (err) {
      process.stdout.write('\r\x1b[K');
      console.log(`  ${c.yellow}Failed to fetch profile: ${err.message}${c.reset}`);
      console.log();
      console.log(`  ${c.dim}Web profile: ${c.cyan}${REGISTRY_URL}/profile${c.reset}`);
      console.log();
    }
    return;
  }

  if (command === 'model') {
    const newModel = targets.filter(t => !t.startsWith('--'))[0];
    const config = loadLlmConfig();
    const current = config?.llm_model;
    const currentProvider = config?.preferred_provider;

    // Direct set: agentaudit model reset
    if (newModel === 'reset' || newModel === 'clear') {
      for (const f of [USER_CRED_FILE, SKILL_CRED_FILE]) {
        if (fs.existsSync(f)) {
          try {
            const data = JSON.parse(fs.readFileSync(f, 'utf8'));
            delete data.llm_model;
            delete data.preferred_provider;
            fs.writeFileSync(f, JSON.stringify(data, null, 2), { mode: 0o600 });
          } catch {}
        }
      }
      console.log(`  ${icons.safe}  Model + provider reset to defaults`);
      return;
    }

    // Direct set: agentaudit model <name> (sets model only, keeps provider)
    if (newModel) {
      saveLlmConfig(newModel);
      console.log(`  ${icons.safe}  Model set to ${c.bold}${newModel}${c.reset}`);
      if (current) console.log(`  ${c.dim}Was: ${current}${c.reset}`);
      return;
    }

    // ── No argument — interactive two-step menu ──

    // Build deduplicated provider list
    const seen = new Set();
    const providerList = [];
    for (const p of LLM_PROVIDERS) {
      if (seen.has(p.provider)) continue;
      seen.add(p.provider);
      // Check if ANY key for this provider is set
      const keys = LLM_PROVIDERS.filter(x => x.provider === p.provider);
      const hasKey = keys.some(x => process.env[x.key]);
      const keyName = p.key;
      providerList.push({
        label: p.name,
        sublabel: hasKey
          ? `${keyName} ${c.green}✔${c.reset}`
          : `${keyName} ${c.red}✗${c.reset}  ${c.dim}set: export ${keyName}=...${c.reset}`,
        value: p.provider,
        hasKey,
        keyName,
      });
    }

    // Show status
    const resolved = resolveProvider();
    console.log(`  ${c.bold}LLM Configuration${c.reset}`);
    console.log();
    if (currentProvider && current) {
      const provInfo = LLM_PROVIDERS.find(p => p.provider === currentProvider);
      console.log(`  Active:  ${c.bold}${c.cyan}${provInfo?.name || currentProvider} → ${current}${c.reset}`);
    } else if (current) {
      console.log(`  Active:  ${c.bold}${c.cyan}${resolved?.name || 'auto'} → ${current}${c.reset}`);
    } else if (resolved) {
      console.log(`  Active:  ${c.dim}${resolved.name} → ${resolved.model} (defaults)${c.reset}`);
    } else {
      console.log(`  Active:  ${c.yellow}no provider configured${c.reset}`);
    }
    console.log();
    console.log(`  ${c.dim}Recommended for deep audits (validated on real-world CVEs):${c.reset}`);
    console.log(`  ${c.dim}  Anthropic  claude-opus-4    — best precision${c.reset}`);
    console.log(`  ${c.dim}  Anthropic  claude-sonnet-4  — best value${c.reset}`);
    console.log(`  ${c.dim}  xAI        grok-4           — complementary detection${c.reset}`);
    console.log(`  ${c.dim}  Google     gemini-3.1-pro   — deepest analysis${c.reset}`);
    console.log(`  ${c.dim}  For multi-model consensus:  agentaudit audit <url> --models opus,sonnet,grok-4,gemini-3.1-pro${c.reset}`);
    console.log();

    // Step A: Provider selection
    const providerChoices = [
      ...providerList,
      { label: '(keep current)', sublabel: '', value: '__keep__', hasKey: true },
    ];

    const selectedProvider = await singleSelect(providerChoices, {
      title: 'Choose provider',
      hint: '↑↓ move  Enter select  Esc cancel',
    });

    if (selectedProvider === null) {
      console.log(`  ${c.dim}Cancelled${c.reset}`);
      return;
    }

    if (selectedProvider === '__keep__') {
      console.log(`  ${c.dim}Keeping current config${c.reset}`);
      return;
    }

    // Check if provider has key set
    const chosenEntry = providerList.find(p => p.value === selectedProvider);
    if (chosenEntry && !chosenEntry.hasKey) {
      console.log();
      console.log(`  ${c.yellow}${chosenEntry.keyName} is not set.${c.reset}`);
      console.log(`  ${c.dim}Run: export ${chosenEntry.keyName}=your-key-here${c.reset}`);
      console.log(`  ${c.dim}Then run "agentaudit model" again.${c.reset}`);
      return;
    }

    // Step B: Model selection for chosen provider
    console.log();
    const providerModels = PROVIDER_MODELS[selectedProvider] || [];
    const modelChoices = [
      ...providerModels,
      { label: '(enter custom model name)', sublabel: '', value: '__custom__' },
      { label: '(reset to provider default)', sublabel: '', value: '__reset__' },
    ];

    const providerName = LLM_PROVIDERS.find(p => p.provider === selectedProvider)?.name || selectedProvider;
    const selectedModel = await singleSelect(modelChoices, {
      title: `Choose model for ${providerName}`,
      hint: '↑↓ move  Enter select  Esc cancel',
    });

    if (selectedModel === null) {
      console.log(`  ${c.dim}Cancelled${c.reset}`);
      return;
    }

    if (selectedModel === '__reset__') {
      // Save provider, clear model (use provider default)
      saveLlmConfig(undefined, selectedProvider);
      // Also clear llm_model from both files
      for (const f of [USER_CRED_FILE, SKILL_CRED_FILE]) {
        if (fs.existsSync(f)) {
          try {
            const data = JSON.parse(fs.readFileSync(f, 'utf8'));
            delete data.llm_model;
            data.preferred_provider = selectedProvider;
            fs.writeFileSync(f, JSON.stringify(data, null, 2), { mode: 0o600 });
          } catch {}
        }
      }
      const defaultModel = LLM_PROVIDERS.find(p => p.provider === selectedProvider)?.model;
      console.log();
      console.log(`  ${icons.safe}  Provider: ${c.bold}${providerName}${c.reset}, model: ${c.dim}${defaultModel} (default)${c.reset}`);
      return;
    }

    if (selectedModel === '__custom__') {
      console.log();
      const custom = await askQuestion(`  Model name: `);
      if (!custom) {
        console.log(`  ${c.dim}Cancelled${c.reset}`);
        return;
      }
      saveLlmConfig(custom, selectedProvider);
      console.log(`  ${icons.safe}  Provider: ${c.bold}${providerName}${c.reset}, model: ${c.bold}${custom}${c.reset}`);
      if (current) console.log(`  ${c.dim}Was: ${currentProvider || 'auto'} → ${current}${c.reset}`);
      return;
    }

    // Normal model selection
    saveLlmConfig(selectedModel, selectedProvider);
    console.log();
    console.log(`  ${icons.safe}  Provider: ${c.bold}${providerName}${c.reset}, model: ${c.bold}${selectedModel}${c.reset}`);
    if (current) console.log(`  ${c.dim}Was: ${currentProvider || 'auto'} → ${current}${c.reset}`);
    console.log();
    console.log(`  ${c.dim}Tip: agentaudit model <name>  to set model directly, or  agentaudit model reset${c.reset}`);
    return;
  }
  
  if (command === 'validate') {
    const paths = targets.filter(t => !t.startsWith('--'));

    // If no path given, find all skills and validate them
    if (paths.length === 0) {
      const skills = findSkills();
      if (skills.length === 0) {
        console.log(`  ${c.yellow}No SKILL.md files found${c.reset}`);
        console.log(`  ${c.dim}Searched: ~/.claude/skills/, ~/.cursor/skills/, .claude/skills/, .cursor/skills/${c.reset}`);
        console.log();
        console.log(`  ${c.dim}Usage: ${c.cyan}agentaudit validate [path/to/SKILL.md]${c.reset}`);
        return;
      }

      console.log(`  ${c.bold}Validating ${skills.length} skill${skills.length !== 1 ? 's' : ''}${c.reset}`);
      console.log();

      let totalErrors = 0;
      let totalWarnings = 0;

      for (const skill of skills) {
        const { errors, warnings, info } = skill.validation;
        totalErrors += errors.length;
        totalWarnings += warnings.length;

        const name = info.name || skill.dirName;
        const hasErrors = errors.length > 0;
        const hasWarnings = warnings.length > 0;

        if (hasErrors) {
          console.log(`  ${c.red}✖${c.reset} ${c.bold}${name}${c.reset}  ${c.dim}${skill.path}${c.reset}`);
          for (const err of errors) console.log(`    ${c.red}✖ ${err}${c.reset}`);
          for (const warn of warnings) console.log(`    ${c.yellow}⚠ ${warn}${c.reset}`);
        } else if (hasWarnings) {
          console.log(`  ${c.yellow}⚠${c.reset} ${c.bold}${name}${c.reset}  ${c.dim}${skill.path}${c.reset}`);
          for (const warn of warnings) console.log(`    ${c.yellow}⚠ ${warn}${c.reset}`);
        } else {
          console.log(`  ${c.green}✔${c.reset} ${c.bold}${name}${c.reset}  ${c.dim}${skill.path}${c.reset}`);
        }

        // Show MCP references
        if (info.mcpServers && info.mcpServers.length > 0) {
          console.log(`    ${c.dim}MCP servers: ${info.mcpServers.join(', ')}${c.reset}`);
        }
        if (info.allowedTools === null) {
          console.log(`    ${c.yellow}⚠ no allowed-tools — unrestricted tool access${c.reset}`);
        }
        console.log();
      }

      // Summary
      console.log(sectionHeader('Validation Summary'));
      console.log();
      if (totalErrors === 0 && totalWarnings === 0) {
        console.log(`  ${c.green}✔ All ${skills.length} skills valid${c.reset}`);
      } else {
        if (totalErrors > 0) console.log(`  ${c.red}✖ ${totalErrors} error${totalErrors !== 1 ? 's' : ''}${c.reset}`);
        if (totalWarnings > 0) console.log(`  ${c.yellow}⚠ ${totalWarnings} warning${totalWarnings !== 1 ? 's' : ''}${c.reset}`);
      }
      console.log();

      if (jsonMode) {
        console.log(JSON.stringify(skills.map(s => ({
          name: s.validation.info.name || s.dirName,
          path: s.path,
          source: s.source,
          errors: s.validation.errors,
          warnings: s.validation.warnings,
          mcpServers: s.validation.info.mcpServers,
          allowedTools: s.validation.info.allowedTools,
        })), null, 2));
      }

      process.exitCode = totalErrors > 0 ? 1 : 0;
      return;
    }

    // Validate specific file(s)
    for (const p of paths) {
      const resolved = path.resolve(p);
      if (!fs.existsSync(resolved)) {
        console.log(`  ${c.red}✖ File not found: ${p}${c.reset}`);
        process.exitCode = 1;
        continue;
      }

      const content = fs.readFileSync(resolved, 'utf8');
      const parsed = parseSkillFrontmatter(content);
      const { errors, warnings, info } = validateSkill(parsed);
      const name = info.name || path.basename(path.dirname(resolved));

      console.log(`  ${c.bold}${name}${c.reset}  ${c.dim}${resolved}${c.reset}`);
      console.log();

      if (errors.length === 0 && warnings.length === 0) {
        console.log(`  ${c.green}✔ Valid skill format${c.reset}`);
      }

      for (const err of errors) console.log(`  ${c.red}✖ ${err}${c.reset}`);
      for (const warn of warnings) console.log(`  ${c.yellow}⚠ ${warn}${c.reset}`);

      if (info.name) console.log(`  ${c.dim}name:${c.reset} ${info.name}`);
      if (info.description) console.log(`  ${c.dim}description:${c.reset} ${info.description.slice(0, 80)}${info.description.length > 80 ? '...' : ''}`);
      if (info.allowedTools) console.log(`  ${c.dim}allowed-tools:${c.reset} ${info.allowedTools.join(', ')}`);
      else if (info.allowedTools === null) console.log(`  ${c.yellow}allowed-tools: none (unrestricted)${c.reset}`);
      if (info.mcpServers?.length > 0) console.log(`  ${c.dim}MCP servers:${c.reset} ${info.mcpServers.join(', ')}`);
      if (info.bodyLines) console.log(`  ${c.dim}body:${c.reset} ${info.bodyLines} lines`);
      console.log();

      if (jsonMode) {
        console.log(JSON.stringify({ name: info.name, path: resolved, errors, warnings, info }, null, 2));
      }

      process.exitCode = errors.length > 0 ? 1 : 0;
    }
    return;
  }

  if (command === 'discover') {
    const scanFlag = targets.includes('--quick') || targets.includes('--scan') || targets.includes('-s');
    const auditFlag = targets.includes('--deep') || targets.includes('--audit') || targets.includes('-a');
    await discoverCommand({ scan: scanFlag, audit: auditFlag });
    return;
  }
  
  if (command === 'lookup' || command === 'check') {
    const names = targets.filter(t => !t.startsWith('--'));
    if (names.length === 0) {
      console.log(`  ${c.red}Error: package name required${c.reset}`);
      console.log(`  ${c.dim}Usage: ${c.cyan}agentaudit lookup <name>${c.dim} — e.g. agentaudit lookup fastmcp${c.reset}`);
      process.exitCode = 2;
      return;
    }
    const results = [];
    for (const t of names) {
      const data = await checkPackage(t);
      results.push(data);
    }
    if (jsonMode) {
      console.log(JSON.stringify(results.length === 1 ? (results[0] || { error: 'not_found' }) : results, null, 2));
    }
    process.exitCode = 0; return;
  }
  
  if (command === 'scan') {
    const deepFlag = targets.includes('--deep');
    const urls = targets.filter(t => !t.startsWith('--'));
    if (urls.length === 0) {
      console.log(`  ${c.red}Error: at least one repository URL required${c.reset}`);
      console.log(`  ${c.dim}Tip: use ${c.cyan}agentaudit discover${c.dim} to find & check locally installed MCP servers${c.reset}`);
      console.log(`  ${c.dim}Tip: use ${c.cyan}agentaudit audit <url>${c.dim} for a deep LLM-powered audit${c.reset}`);
      process.exitCode = 2;
      return;
    }
    
    // --deep redirects to audit flow (--remote supported)
    if (deepFlag) {
      const auditFn = remoteFlag ? remoteAudit : auditRepo;
      let hasFindings = false;
      const allReports = [];
      for (const url of urls) {
        const report = await auditFn(url);
        if (Array.isArray(report)) {
          allReports.push(...report.filter(Boolean));
          if (report.some(r => r?.findings?.length > 0)) hasFindings = true;
        } else if (report) {
          allReports.push(report);
          if (report.findings?.length > 0) hasFindings = true;
        }
      }
      if (outputFormat === 'sarif') {
        console.log(JSON.stringify(toSarif(allReports), null, 2));
      }
      process.exitCode = hasFindings ? 1 : 0;
      return;
    }
    
    const results = [];
    let hadErrors = false;
    for (const url of urls) {
      const result = await scanRepo(url);
      if (result) results.push(result);
      else hadErrors = true;
    }
    
    if (outputFormat === 'sarif') {
      const sarif = toSarif(results.map(r => ({
        findings: (r.findings || []).map(f => ({ ...f, pattern_id: f.id })),
      })));
      console.log(JSON.stringify(sarif, null, 2));
    } else if (jsonMode || outputFormat === 'json') {
      const jsonOut = results.map(r => ({
        slug: r.slug,
        url: r.url,
        findings: r.findings.map(f => ({
          severity: f.severity,
          title: f.title,
          file: f.file,
          line: f.line,
          snippet: f.snippet,
        })),
        fileCount: r.files,
        duration: r.duration,
      }));
      console.log(JSON.stringify(jsonOut.length === 1 ? jsonOut[0] : jsonOut, null, 2));
    } else if (results.length > 1) {
      printSummary(results);
    }
    
    if (hadErrors && results.length === 0) { process.exitCode = 2; return; }
    const totalFindings = results.reduce((sum, r) => sum + r.findings.length, 0);
    process.exitCode = totalFindings > 0 ? 1 : 0;
    return;
  }
  
  if (command === 'audit') {
    // Extract URLs: skip option flags and their values
    const optionsWithValues = new Set(['--model', '--verify', '--format', '--models']);
    const urls = [];
    for (let i = 0; i < targets.length; i++) {
      if (targets[i].startsWith('--')) {
        if (optionsWithValues.has(targets[i]) && i + 1 < targets.length) i++; // skip next (value)
        continue;
      }
      urls.push(targets[i]);
    }
    if (urls.length === 0) {
      console.log(`  ${c.red}Error: at least one repository URL required${c.reset}`);
      console.log(`  ${c.dim}Usage: ${c.cyan}agentaudit audit <url>${c.dim} — e.g. agentaudit audit https://github.com/owner/repo${c.reset}`);
      console.log(`  ${c.dim}Tip: use ${c.cyan}agentaudit discover --deep${c.dim} to find & audit locally installed MCP servers${c.reset}`);
      process.exitCode = 2;
      return;
    }

    // --remote: use server-side scan
    if (remoteFlag) {
      let hasFindings = false;
      const allReports = [];
      for (const url of urls) {
        const result = await remoteAudit(url);
        if (result) {
          allReports.push(result);
          if (result.findings?.length > 0) hasFindings = true;
        }
      }
      if (outputFormat === 'sarif') {
        console.log(JSON.stringify(toSarif(allReports), null, 2));
      }
      process.exitCode = hasFindings ? 1 : 0;
      return;
    }

    let hasFindings = false;
    const allReports = [];
    for (const url of urls) {
      const result = await auditRepo(url);
      // Multi-model returns array, single-model returns object
      if (Array.isArray(result)) {
        allReports.push(...result.filter(Boolean));
        if (result.some(r => r?.findings?.length > 0)) hasFindings = true;
      } else if (result) {
        allReports.push(result);
        if (result.findings?.length > 0) hasFindings = true;
      }
    }

    if (outputFormat === 'sarif') {
      const sarif = toSarif(allReports);
      console.log(JSON.stringify(sarif, null, 2));
    }

    process.exitCode = hasFindings ? 1 : 0;
    return;
  }
  
  console.log(`  ${c.red}Unknown command: ${command}${c.reset}`);
  console.log(`  ${c.dim}Run ${c.cyan}agentaudit help${c.dim} for available commands${c.reset}`);
  process.exitCode = 2;
}

main().catch(err => {
  console.error(`${c.red}Error: ${err.message}${c.reset}`);
  process.exitCode = 2;
});
