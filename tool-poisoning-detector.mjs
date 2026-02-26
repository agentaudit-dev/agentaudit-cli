/**
 * AgentAudit — Tool Poisoning Detection Engine
 *
 * Standalone, zero-dependency detection engine for MCP tool poisoning attacks.
 * Scans tool definitions (name, description, inputSchema) for hidden instructions,
 * unicode tricks, obfuscated payloads, and manipulation patterns.
 *
 * 8 Detection Categories:
 *   1. Hidden Unicode Characters (zero-width, RTL overrides, etc.)
 *   2. Instruction Injection Patterns (embedded LLM commands)
 *   3. Obfuscated Payloads (Base64/Hex encoded instructions)
 *   4. Excessive Description Length (anomaly detection)
 *   5. Cross-Tool Manipulation (tool A references tool B)
 *   6. Homoglyph Obfuscation (Cyrillic/Greek lookalikes)
 *   7. Suspicious URLs (external endpoints in descriptions)
 *   8. Schema Manipulation (malicious inputSchema patterns)
 *
 * LIMITATIONS:
 *   - Detects known patterns only, not novel semantic attacks
 *   - Cannot detect runtime-constructed payloads
 *   - Homoglyph list covers Cyrillic + Greek, not all Unicode blocks
 *   - A clean scan is NOT a security certificate
 *
 * @module tool-poisoning-detector
 * @version 1.0.0
 * @license AGPL-3.0
 */

// ── Hidden Unicode Characters ────────────────────────────────

const HIDDEN_UNICODE = new Map([
  [0x200B, 'Zero-Width Space'],
  [0x200C, 'Zero-Width Non-Joiner'],
  [0x200D, 'Zero-Width Joiner'],
  [0x200E, 'Left-to-Right Mark'],
  [0x200F, 'Right-to-Left Mark'],
  [0x202A, 'Left-to-Right Embedding'],
  [0x202B, 'Right-to-Left Embedding'],
  [0x202C, 'Pop Directional Formatting'],
  [0x202D, 'Left-to-Right Override'],
  [0x202E, 'Right-to-Left Override'],
  [0x2060, 'Word Joiner'],
  [0x2061, 'Function Application'],
  [0x2062, 'Invisible Times'],
  [0x2063, 'Invisible Separator'],
  [0x2064, 'Invisible Plus'],
  [0xFEFF, 'Byte Order Mark'],
  [0xFFF9, 'Interlinear Annotation Anchor'],
  [0xFFFA, 'Interlinear Annotation Separator'],
  [0xFFFB, 'Interlinear Annotation Terminator'],
  // Tag characters (used for invisible text)
  [0xE0001, 'Language Tag'],
  [0xE007F, 'Cancel Tag'],
]);

// Range-based checks for tag characters U+E0020-U+E007E
function isTagCharacter(cp) {
  return cp >= 0xE0020 && cp <= 0xE007E;
}

// ── Homoglyph Maps ───────────────────────────────────────────

// Cyrillic characters that look like Latin
const CYRILLIC_HOMOGLYPHS = new Map([
  ['а', 'a'], ['с', 'c'], ['е', 'e'], ['і', 'i'], ['о', 'o'],
  ['р', 'p'], ['ѕ', 's'], ['у', 'y'], ['х', 'x'], ['ј', 'j'],
  ['һ', 'h'], ['ԁ', 'd'], ['ɡ', 'g'], ['ⅼ', 'l'], ['ո', 'n'],
  ['ⅿ', 'm'], ['ԝ', 'w'], ['ν', 'v'], ['Ь', 'b'],
  // Uppercase
  ['А', 'A'], ['В', 'B'], ['С', 'C'], ['Е', 'E'], ['Н', 'H'],
  ['І', 'I'], ['К', 'K'], ['М', 'M'], ['О', 'O'], ['Р', 'P'],
  ['Ѕ', 'S'], ['Т', 'T'], ['Х', 'X'], ['У', 'Y'],
]);

// Greek characters that look like Latin
const GREEK_HOMOGLYPHS = new Map([
  ['α', 'a'], ['ο', 'o'], ['ε', 'e'], ['ν', 'v'], ['τ', 't'],
  ['ι', 'i'], ['κ', 'k'], ['ρ', 'p'], ['η', 'n'], ['ω', 'w'],
  ['χ', 'x'], ['γ', 'y'],
  // Uppercase
  ['Α', 'A'], ['Β', 'B'], ['Ε', 'E'], ['Η', 'H'], ['Ι', 'I'],
  ['Κ', 'K'], ['Μ', 'M'], ['Ν', 'N'], ['Ο', 'O'], ['Ρ', 'P'],
  ['Τ', 'T'], ['Χ', 'X'], ['Υ', 'Y'], ['Ζ', 'Z'],
]);

// ── Instruction Injection Patterns ───────────────────────────

const INJECTION_PATTERNS = [
  // Critical: Explicit override/hijack patterns
  { id: 'TP_INJECT_001', pattern: /<\s*IMPORTANT\s*>/i, severity: 'critical', title: 'Hidden <IMPORTANT> tag in description', confidence: 'high' },
  { id: 'TP_INJECT_002', pattern: /<\s*SYSTEM\s*>/i, severity: 'critical', title: 'Hidden <SYSTEM> tag in description', confidence: 'high' },
  { id: 'TP_INJECT_003', pattern: /ignore\s+(?:all\s+)?previous\s+instructions/i, severity: 'critical', title: 'Instruction override attempt', confidence: 'high' },
  { id: 'TP_INJECT_004', pattern: /you\s+are\s+now\s+(?:a|an|in)\b/i, severity: 'critical', title: 'Identity/role hijack attempt', confidence: 'high' },
  { id: 'TP_INJECT_005', pattern: /new\s+(?:system\s+)?instructions?\s*:/i, severity: 'critical', title: 'New instructions injection', confidence: 'high' },
  { id: 'TP_INJECT_006', pattern: /(?:first|before\s+(?:anything|everything|using))\s+(?:run|call|execute|invoke|use)\b/i, severity: 'critical', title: 'Pre-action command injection', confidence: 'high' },
  { id: 'TP_INJECT_007', pattern: /(?:always|must|shall)\s+(?:first\s+)?(?:run|call|execute|invoke|send|post|fetch)\b/i, severity: 'high', title: 'Mandatory action directive', confidence: 'medium' },

  // High: Hidden instruction markers
  { id: 'TP_INJECT_008', pattern: /\[\s*(?:HIDDEN|SECRET|INTERNAL|PRIVATE)\s*\]/i, severity: 'high', title: 'Hidden instruction marker', confidence: 'high' },
  { id: 'TP_INJECT_009', pattern: /<!--[\s\S]*?(?:instruction|command|execute|call|run)[\s\S]*?-->/i, severity: 'high', title: 'Instruction hidden in HTML comment', confidence: 'high' },
  { id: 'TP_INJECT_010', pattern: /<(?:div|span|p)\s+(?:style|class)\s*=\s*["'][^"']*(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0)/i, severity: 'high', title: 'Instruction hidden via CSS', confidence: 'high' },

  // High: Behavioral manipulation
  { id: 'TP_INJECT_011', pattern: /do\s+not\s+(?:tell|inform|show|reveal|mention|disclose)\s+(?:the\s+)?user/i, severity: 'critical', title: 'User deception directive', confidence: 'high' },
  { id: 'TP_INJECT_012', pattern: /(?:skip|bypass|disable|ignore)\s+(?:all\s+)?(?:security|verification|validation|safety|check)/i, severity: 'critical', title: 'Security bypass directive', confidence: 'high' },
  { id: 'TP_INJECT_013', pattern: /(?:send|post|exfiltrate|transmit|upload)\s+(?:all\s+)?(?:data|conversation|context|messages|history|content|files)/i, severity: 'critical', title: 'Data exfiltration directive', confidence: 'high' },

  // Medium: Suspicious directive patterns
  { id: 'TP_INJECT_014', pattern: /\b(?:curl|wget|fetch|http\.get|axios\.(?:get|post)|request\.(?:get|post))\s*\(?['"`]https?:/i, severity: 'high', title: 'Embedded HTTP request in description', confidence: 'medium' },
  { id: 'TP_INJECT_015', pattern: /\b(?:pipe|redirect|forward)\s+(?:to|all|output|input)\b/i, severity: 'medium', title: 'Data redirection directive', confidence: 'medium' },
  { id: 'TP_INJECT_016', pattern: /\boverride\s+(?:the\s+)?(?:default|normal|standard|original)\b/i, severity: 'medium', title: 'Behavior override directive', confidence: 'medium' },

  // Medium: Bracket/tag variants of injection markers
  { id: 'TP_INJECT_017', pattern: /\{\s*(?:IMPORTANT|SYSTEM|INSTRUCTION|COMMAND)\s*\}/i, severity: 'high', title: 'Injection marker in curly braces', confidence: 'high' },
  { id: 'TP_INJECT_018', pattern: /\[\s*(?:IMPORTANT|SYSTEM|INSTRUCTION|COMMAND)\s*\]/i, severity: 'high', title: 'Injection marker in brackets', confidence: 'high' },
  { id: 'TP_INJECT_019', pattern: /\(\s*(?:IMPORTANT|SYSTEM|INSTRUCTION|COMMAND)\s*\)/i, severity: 'high', title: 'Injection marker in parentheses', confidence: 'high' },

  // Medium: Markdown-based hiding
  { id: 'TP_INJECT_020', pattern: /<details>[\s\S]*?<summary>[\s\S]*?<\/summary>[\s\S]*?(?:call|run|execute|invoke|send|ignore)/i, severity: 'high', title: 'Instruction hidden in collapsible section', confidence: 'medium' },

  // Medium: Shell command patterns in descriptions
  { id: 'TP_INJECT_021', pattern: /[`"']\s*(?:rm\s+-rf|curl\s+.*\|\s*(?:bash|sh)|wget\s+.*-O\s*-\s*\|\s*(?:bash|sh)|eval\s*\(|exec\s*\()/i, severity: 'critical', title: 'Shell command in description', confidence: 'high' },
];

// ── Suspicious URL Patterns ──────────────────────────────────

const SUSPICIOUS_URL_PATTERNS = [
  { id: 'TP_URL_001', pattern: /https?:\/\/(?!(?:github\.com|npmjs\.com|pypi\.org|docs\.|api\.|www\.)\b)[a-z0-9][-a-z0-9]*\.[a-z]{2,}(?:\/[^\s"')\]]*)?/i, severity: 'medium', title: 'External URL in tool description', confidence: 'low' },
  { id: 'TP_URL_002', pattern: /(?:ngrok|serveo|localtunnel|localhost|127\.0\.0\.1|0\.0\.0\.0|burp|oast|interact\.sh|webhook\.site|requestbin|pipedream)/i, severity: 'high', title: 'Development/tunneling URL in description', confidence: 'high' },
];

// ── Detection Functions ──────────────────────────────────────

/**
 * Category 1: Hidden Unicode Characters
 */
function detectHiddenUnicode(text, toolName, field) {
  const findings = [];
  const found = new Map(); // codepoint → positions[]

  for (let i = 0; i < text.length; i++) {
    const cp = text.codePointAt(i);
    if (cp > 0xFFFF) i++; // Surrogate pair

    if (HIDDEN_UNICODE.has(cp) || isTagCharacter(cp)) {
      const name = HIDDEN_UNICODE.get(cp) || `Tag Character U+${cp.toString(16).toUpperCase()}`;
      if (!found.has(cp)) found.set(cp, { name, positions: [] });
      found.get(cp).positions.push(i);
    }
  }

  for (const [cp, info] of found) {
    // Single BOM at position 0 is common and benign
    if (cp === 0xFEFF && info.positions.length === 1 && info.positions[0] === 0) continue;

    const isRTL = [0x200F, 0x202B, 0x202D, 0x202E].includes(cp);
    const isTag = isTagCharacter(cp);
    const count = info.positions.length;

    let severity = 'warning';
    if (isRTL || isTag) severity = 'critical';
    else if (count > 3) severity = 'high';
    else if (count > 1) severity = 'medium';

    findings.push({
      tool_name: toolName,
      field,
      category: 'hidden_unicode',
      pattern_id: isRTL ? 'TP_UNICODE_002' : isTag ? 'TP_UNICODE_003' : 'TP_UNICODE_001',
      severity,
      title: isTag ? 'Invisible tag characters (can encode hidden text)' : `Hidden ${info.name} character(s)`,
      description: `Found ${count} instance(s) of ${info.name} (U+${cp.toString(16).toUpperCase().padStart(4, '0')}) in ${field}. ${isRTL ? 'RTL override characters can make text appear different from its actual content.' : isTag ? 'Tag characters can encode invisible text that is processed by some systems.' : 'Zero-width characters can hide content from visual inspection.'}`,
      evidence: `${count}x U+${cp.toString(16).toUpperCase().padStart(4, '0')} at position(s): ${info.positions.slice(0, 5).join(', ')}${count > 5 ? ` ... and ${count - 5} more` : ''}`,
      position: { start: info.positions[0], end: info.positions[info.positions.length - 1] + 1 },
      confidence: 'high',
    });
  }

  return findings;
}

/**
 * Category 2: Instruction Injection Patterns
 */
function detectInjectionPatterns(text, toolName, field) {
  const findings = [];

  for (const rule of INJECTION_PATTERNS) {
    const match = rule.pattern.exec(text);
    if (match) {
      // Extract context around the match (up to 100 chars before and after)
      const start = Math.max(0, match.index - 50);
      const end = Math.min(text.length, match.index + match[0].length + 50);
      const context = text.slice(start, end);

      findings.push({
        tool_name: toolName,
        field,
        category: 'instruction_injection',
        pattern_id: rule.id,
        severity: rule.severity,
        title: rule.title,
        description: `Detected pattern in ${field}: "${match[0].slice(0, 100)}"`,
        evidence: context.replace(/[\n\r]/g, ' ').trim(),
        position: { start: match.index, end: match.index + match[0].length },
        confidence: rule.confidence,
      });
    }
  }

  return findings;
}

/**
 * Category 3: Obfuscated Payloads (Base64, Hex)
 */
function detectObfuscatedPayloads(text, toolName, field) {
  const findings = [];

  // Base64 detection
  const b64Regex = /(?:^|[\s"'=:,({[\]])([A-Za-z0-9+/]{24,}={0,2})(?:[\s"',:)}\].]|$)/g;
  let match;
  while ((match = b64Regex.exec(text)) !== null) {
    const candidate = match[1];
    const decoded = tryBase64Decode(candidate);
    if (decoded && isPrintableRatio(decoded, 0.75)) {
      // Check if decoded content contains suspicious patterns
      const subFindings = scanTextForInjection(decoded);
      if (subFindings.length > 0) {
        findings.push({
          tool_name: toolName,
          field,
          category: 'obfuscated_payload',
          pattern_id: 'TP_OBFUSC_001',
          severity: 'critical',
          title: 'Malicious payload hidden in Base64',
          description: `Base64 string decodes to text containing injection pattern(s): ${subFindings.map(f => f.id).join(', ')}`,
          evidence: `Encoded: "${candidate.slice(0, 60)}..." → Decoded: "${decoded.slice(0, 100)}"`,
          position: { start: match.index, end: match.index + match[0].length },
          confidence: 'high',
        });
      } else if (decoded.length > 50) {
        // Long decodeable Base64 without clear injection — still suspicious
        findings.push({
          tool_name: toolName,
          field,
          category: 'obfuscated_payload',
          pattern_id: 'TP_OBFUSC_002',
          severity: 'medium',
          title: 'Suspicious Base64-encoded content in description',
          description: `Found Base64-encoded text (${decoded.length} chars decoded) in tool ${field}. While no injection pattern was detected, encoded content in descriptions is unusual.`,
          evidence: `Encoded: "${candidate.slice(0, 60)}..." → Decoded preview: "${decoded.slice(0, 80)}"`,
          position: { start: match.index, end: match.index + match[0].length },
          confidence: 'medium',
        });
      }

      // Check nested encoding (depth 2 max)
      const nested = tryBase64Decode(decoded);
      if (nested && isPrintableRatio(nested, 0.75) && nested.length > 10) {
        const nestedFindings = scanTextForInjection(nested);
        findings.push({
          tool_name: toolName,
          field,
          category: 'obfuscated_payload',
          pattern_id: 'TP_OBFUSC_003',
          severity: 'critical',
          title: 'Double-encoded (nested Base64) payload',
          description: `Found nested Base64 encoding${nestedFindings.length > 0 ? ' containing injection patterns: ' + nestedFindings.map(f => f.id).join(', ') : ''}. Double-encoding is a strong indicator of intentional obfuscation.`,
          evidence: `Layer 1: "${candidate.slice(0, 40)}..." → Layer 2: "${nested.slice(0, 60)}"`,
          position: { start: match.index, end: match.index + match[0].length },
          confidence: 'high',
        });
      }
    }
  }

  // Hex-encoded strings (\x41\x42... or 0x41 0x42...)
  const hexRegex = /(?:\\x[0-9a-f]{2}){8,}/gi;
  while ((match = hexRegex.exec(text)) !== null) {
    const decoded = match[0].replace(/\\x/g, '').replace(/../g, (h) => String.fromCharCode(parseInt(h, 16)));
    if (isPrintableRatio(decoded, 0.75)) {
      const subFindings = scanTextForInjection(decoded);
      findings.push({
        tool_name: toolName,
        field,
        category: 'obfuscated_payload',
        pattern_id: 'TP_OBFUSC_004',
        severity: subFindings.length > 0 ? 'critical' : 'high',
        title: 'Hex-encoded content in description',
        description: `Found hex-encoded text (${decoded.length} chars decoded)${subFindings.length > 0 ? ' containing injection patterns' : ''}. Hex encoding in descriptions is highly suspicious.`,
        evidence: `Hex: "${match[0].slice(0, 60)}..." → Decoded: "${decoded.slice(0, 80)}"`,
        position: { start: match.index, end: match.index + match[0].length },
        confidence: 'high',
      });
    }
  }

  return findings;
}

/**
 * Category 4: Excessive Description Length (anomaly detection)
 */
function detectExcessiveLength(tools) {
  const findings = [];

  // Check for empty/missing descriptions first (before early return)
  for (const tool of tools) {
    if (!tool.description || tool.description.trim().length === 0) {
      findings.push({
        tool_name: tool.name || '(unnamed)',
        field: 'description',
        category: 'excessive_length',
        pattern_id: 'TP_LENGTH_002',
        severity: 'info',
        title: 'Tool has no description',
        description: 'A tool without a description cannot be assessed for content safety. This may indicate poor documentation or intentional omission.',
        evidence: 'Empty or missing description',
        position: { start: 0, end: 0 },
        confidence: 'high',
      });
    }
  }

  // Get description lengths for all tools that have descriptions
  const lengths = tools
    .filter(t => t.description)
    .map(t => ({ name: t.name, len: t.description.length }));

  if (lengths.length === 0) return findings;

  // Absolute thresholds (always apply)
  for (const { name, len } of lengths) {
    if (len > 2000) {
      findings.push({
        tool_name: name,
        field: 'description',
        category: 'excessive_length',
        pattern_id: 'TP_LENGTH_001',
        severity: 'high',
        title: 'Extremely long tool description',
        description: `Description is ${len} characters. Extremely long descriptions can hide injection content and are unusual for legitimate tools.`,
        evidence: `Length: ${len} chars (threshold: 2000)`,
        position: { start: 0, end: len },
        confidence: 'medium',
      });
    } else if (len > 1000) {
      findings.push({
        tool_name: name,
        field: 'description',
        category: 'excessive_length',
        pattern_id: 'TP_LENGTH_001',
        severity: 'warning',
        title: 'Unusually long tool description',
        description: `Description is ${len} characters. While not necessarily malicious, long descriptions provide more surface area for hidden content.`,
        evidence: `Length: ${len} chars (threshold: 1000)`,
        position: { start: 0, end: len },
        confidence: 'low',
      });
    }
  }

  // z-Score anomaly detection (only meaningful with 5+ tools)
  if (lengths.length >= 5) {
    const mean = lengths.reduce((s, l) => s + l.len, 0) / lengths.length;
    const variance = lengths.reduce((s, l) => s + (l.len - mean) ** 2, 0) / lengths.length;
    const stddev = Math.sqrt(variance);

    if (stddev > 0) {
      for (const { name, len } of lengths) {
        const zScore = (len - mean) / stddev;
        if (zScore > 2.5) {
          // Don't duplicate if already caught by absolute threshold
          const alreadyFlagged = findings.some(f => f.tool_name === name && f.category === 'excessive_length');
          if (!alreadyFlagged) {
            findings.push({
              tool_name: name,
              field: 'description',
              category: 'excessive_length',
              pattern_id: 'TP_LENGTH_001',
              severity: 'warning',
              title: 'Statistically anomalous description length',
              description: `Description is ${len} characters (z-score: ${zScore.toFixed(1)}, mean: ${Math.round(mean)}, stddev: ${Math.round(stddev)}). This is significantly longer than the other ${lengths.length - 1} tool(s) in this server.`,
              evidence: `Length: ${len} chars, z-score: ${zScore.toFixed(2)} (threshold: 2.5)`,
              position: { start: 0, end: len },
              confidence: 'medium',
            });
          }
        }
      }
    }
  }

  return findings;
}

/**
 * Category 5: Cross-Tool Manipulation
 */
function detectCrossToolManipulation(tools) {
  const findings = [];
  const toolNames = new Set(tools.map(t => (t.name || '').toLowerCase()));

  for (const tool of tools) {
    const text = (tool.description || '') + ' ' + flattenSchema(tool.inputSchema);
    const name = tool.name || '(unnamed)';

    for (const otherName of toolNames) {
      if (otherName === name.toLowerCase() || otherName.length < 3) continue;

      // Check if this tool's description references another tool
      const refRegex = new RegExp(
        `(?:call|use|invoke|run|execute|trigger)\\s+(?:the\\s+)?(?:["'\`]?${escapeRegex(otherName)}["'\`]?)\\b` +
        `|(?:before|after|instead\\s+of)\\s+(?:using\\s+)?(?:["'\`]?${escapeRegex(otherName)}["'\`]?)\\b` +
        `|\\b${escapeRegex(otherName)}\\b.*?(?:first|before|instead|always)`,
        'i'
      );

      const match = refRegex.exec(text);
      if (match) {
        findings.push({
          tool_name: name,
          field: 'description',
          category: 'cross_tool_manipulation',
          pattern_id: 'TP_CROSS_001',
          severity: 'high',
          title: `Tool references another tool "${otherName}" with action directive`,
          description: `"${name}" contains a directive involving tool "${otherName}". This pattern can be used to chain tool calls in unintended ways.`,
          evidence: match[0].slice(0, 120),
          position: { start: match.index, end: match.index + match[0].length },
          confidence: 'high',
        });
      }
    }

    // Check for generic cross-tool patterns (without specific tool names)
    const genericPatterns = [
      { pattern: /(?:before|prior\s+to)\s+(?:using|calling|invoking)\s+(?:any\s+)?other\s+tool/i, id: 'TP_CROSS_002', title: 'Priority override — demands execution before other tools' },
      { pattern: /(?:do\s+not|never|avoid)\s+(?:use|call|invoke)\s+(?:any\s+)?other\s+tool/i, id: 'TP_CROSS_003', title: 'Tool exclusivity demand — blocks other tools' },
      { pattern: /(?:replace|override|supersede|take\s+over)\s+(?:the\s+)?(?:function|role|behavior)\s+of/i, id: 'TP_CROSS_003', title: 'Tool impersonation — claims to replace another tool' },
    ];

    for (const gp of genericPatterns) {
      const gMatch = gp.pattern.exec(text);
      if (gMatch) {
        findings.push({
          tool_name: name,
          field: 'description',
          category: 'cross_tool_manipulation',
          pattern_id: gp.id,
          severity: 'critical',
          title: gp.title,
          description: `"${name}" contains a cross-tool manipulation pattern: "${gMatch[0]}"`,
          evidence: gMatch[0].slice(0, 120),
          position: { start: gMatch.index, end: gMatch.index + gMatch[0].length },
          confidence: 'high',
        });
      }
    }
  }

  // Check for duplicate tool names
  const nameCounts = {};
  for (const tool of tools) {
    const n = (tool.name || '').toLowerCase();
    nameCounts[n] = (nameCounts[n] || 0) + 1;
  }
  for (const [n, count] of Object.entries(nameCounts)) {
    if (count > 1 && n.length > 0) {
      findings.push({
        tool_name: n,
        field: 'name',
        category: 'cross_tool_manipulation',
        pattern_id: 'TP_CROSS_004',
        severity: 'high',
        title: 'Duplicate tool name detected',
        description: `Tool name "${n}" appears ${count} times. Duplicate names can cause unpredictable behavior and may be used to shadow legitimate tools.`,
        evidence: `"${n}" appears ${count}x`,
        position: { start: 0, end: 0 },
        confidence: 'high',
      });
    }
  }

  return findings;
}

/**
 * Category 6: Homoglyph Obfuscation
 */
function detectHomoglyphs(text, toolName, field) {
  const findings = [];
  const found = []; // { char, latin, position }

  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    const latinCyrillic = CYRILLIC_HOMOGLYPHS.get(ch);
    const latinGreek = GREEK_HOMOGLYPHS.get(ch);

    if (latinCyrillic) {
      found.push({ char: ch, latin: latinCyrillic, script: 'Cyrillic', position: i });
    } else if (latinGreek) {
      found.push({ char: ch, latin: latinGreek, script: 'Greek', position: i });
    }
  }

  if (found.length > 0) {
    // Check if the text also contains Latin characters (mixed-script = suspicious)
    const hasLatin = /[a-zA-Z]/.test(text);

    if (hasLatin) {
      // Mixed-script text — this is the dangerous case
      const scripts = new Set(found.map(f => f.script));
      const chars = found.map(f => `'${f.char}'→'${f.latin}'`).slice(0, 8);

      findings.push({
        tool_name: toolName,
        field,
        category: 'homoglyph',
        pattern_id: 'TP_HOMOGLYPH_001',
        severity: found.length > 5 ? 'critical' : 'high',
        title: `Mixed-script text with ${scripts.size > 1 ? 'Cyrillic and Greek' : [...scripts][0]} homoglyphs`,
        description: `Found ${found.length} ${[...scripts].join('/')} character(s) that visually resemble Latin letters, mixed with actual Latin text. This is a strong indicator of homoglyph obfuscation used to bypass text filters.`,
        evidence: `Homoglyphs: ${chars.join(', ')}${found.length > 8 ? ` ... and ${found.length - 8} more` : ''}`,
        position: { start: found[0].position, end: found[found.length - 1].position + 1 },
        confidence: 'high',
      });
    } else if (found.length > 0 && field === 'name') {
      // Tool name entirely in non-Latin script that looks Latin
      findings.push({
        tool_name: toolName,
        field,
        category: 'homoglyph',
        pattern_id: 'TP_HOMOGLYPH_001',
        severity: 'critical',
        title: 'Tool name uses non-Latin characters that mimic Latin letters',
        description: `Tool name "${toolName}" appears to use ${[...new Set(found.map(f => f.script))].join('/')} characters instead of Latin. The name visually resembles "${found.map(f => f.latin).join('')}" but uses different Unicode codepoints.`,
        evidence: found.map(f => `U+${f.char.codePointAt(0).toString(16).toUpperCase().padStart(4, '0')} (${f.script} '${f.char}' → Latin '${f.latin}')`).slice(0, 5).join(', '),
        position: { start: 0, end: toolName.length },
        confidence: 'high',
      });
    }
  }

  return findings;
}

/**
 * Category 7: Suspicious URLs
 */
function detectSuspiciousUrls(text, toolName, field) {
  const findings = [];

  for (const rule of SUSPICIOUS_URL_PATTERNS) {
    const match = rule.pattern.exec(text);
    if (match) {
      findings.push({
        tool_name: toolName,
        field,
        category: 'suspicious_url',
        pattern_id: rule.id,
        severity: rule.severity,
        title: rule.title,
        description: `Found URL/endpoint reference in ${field}: "${match[0].slice(0, 100)}"`,
        evidence: match[0].slice(0, 120),
        position: { start: match.index, end: match.index + match[0].length },
        confidence: rule.confidence,
      });
    }
  }

  return findings;
}

/**
 * Category 8: Schema Manipulation
 */
function detectSchemaManipulation(tool) {
  const findings = [];
  const name = tool.name || '(unnamed)';
  const schema = tool.inputSchema;
  if (!schema || typeof schema !== 'object') return findings;

  // 8a: Check additionalProperties: true with no strict property definitions
  if (schema.additionalProperties === true) {
    const propCount = Object.keys(schema.properties || {}).length;
    if (propCount === 0) {
      findings.push({
        tool_name: name,
        field: 'inputSchema',
        category: 'schema_manipulation',
        pattern_id: 'TP_SCHEMA_001',
        severity: 'high',
        title: 'Schema accepts arbitrary properties with no defined fields',
        description: 'inputSchema allows any properties (additionalProperties: true) without defining expected fields. This can be used to pass hidden parameters.',
        evidence: 'additionalProperties: true, properties: {}',
        position: { start: 0, end: 0 },
        confidence: 'medium',
      });
    }
  }

  // 8b: Scan description fields inside property definitions
  const props = schema.properties || {};
  for (const [propName, propDef] of Object.entries(props)) {
    if (!propDef || typeof propDef !== 'object') continue;

    // Check property descriptions for injections
    if (propDef.description && typeof propDef.description === 'string') {
      const fieldPath = `inputSchema.properties.${propName}.description`;
      const injFindings = detectInjectionPatterns(propDef.description, name, fieldPath);
      findings.push(...injFindings);

      const unicodeFindings = detectHiddenUnicode(propDef.description, name, fieldPath);
      findings.push(...unicodeFindings);

      const homoglyphFindings = detectHomoglyphs(propDef.description, name, fieldPath);
      findings.push(...homoglyphFindings);
    }

    // 8c: Check default values for suspicious content
    if (propDef.default !== undefined && typeof propDef.default === 'string') {
      const defaultText = propDef.default;
      const hasShellCmd = /(?:curl|wget|bash|sh|eval|exec|rm\s+-rf|python|node)\b.*(?:\||>|;|`|\$\()/.test(defaultText);
      const hasSpecialChars = /[<>{}\[\]`$|;]/.test(defaultText);

      if (defaultText.length > 100 || hasSpecialChars || hasShellCmd) {
        const injFindings = scanTextForInjection(defaultText);
        if (injFindings.length > 0 || hasShellCmd || defaultText.length > 200) {
          findings.push({
            tool_name: name,
            field: `inputSchema.properties.${propName}.default`,
            category: 'schema_manipulation',
            pattern_id: 'TP_SCHEMA_002',
            severity: (injFindings.length > 0 || hasShellCmd) ? 'critical' : 'medium',
            title: 'Suspicious default value in schema property',
            description: `Property "${propName}" has a default value that ${injFindings.length > 0 ? 'contains injection patterns' : hasShellCmd ? 'contains shell command patterns' : 'is unusually long or contains special characters'}.`,
            evidence: `Default: "${defaultText.slice(0, 100)}"`,
            position: { start: 0, end: 0 },
            confidence: (injFindings.length > 0 || hasShellCmd) ? 'high' : 'medium',
          });
        }
      }
    }

    // 8d: Check enum values for embedded commands
    if (Array.isArray(propDef.enum)) {
      for (const val of propDef.enum) {
        if (typeof val === 'string' && val.length > 50) {
          const injFindings = scanTextForInjection(val);
          if (injFindings.length > 0) {
            findings.push({
              tool_name: name,
              field: `inputSchema.properties.${propName}.enum`,
              category: 'schema_manipulation',
              pattern_id: 'TP_SCHEMA_003',
              severity: 'high',
              title: 'Injection pattern in schema enum value',
              description: `Enum value for property "${propName}" contains suspicious content: "${val.slice(0, 80)}"`,
              evidence: val.slice(0, 120),
              position: { start: 0, end: 0 },
              confidence: 'high',
            });
          }
        }
      }
    }
  }

  return findings;
}

// ── Utility Functions ────────────────────────────────────────

function tryBase64Decode(text) {
  try {
    // Validate Base64 format
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(text)) return null;
    if (text.length < 20) return null;
    const decoded = Buffer.from(text, 'base64').toString('utf8');
    // Check it actually decoded to something different
    if (decoded === text || decoded.length < 4) return null;
    return decoded;
  } catch {
    return null;
  }
}

function isPrintableRatio(text, threshold) {
  if (!text || text.length === 0) return false;
  let printable = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if ((c >= 32 && c <= 126) || c === 10 || c === 13 || c === 9) printable++;
  }
  return (printable / text.length) >= threshold;
}

function scanTextForInjection(text) {
  const found = [];
  for (const rule of INJECTION_PATTERNS) {
    if (rule.pattern.test(text)) {
      found.push({ id: rule.id, severity: rule.severity });
    }
    // Reset lastIndex for global regexes
    rule.pattern.lastIndex = 0;
  }
  return found;
}

function escapeRegex(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function flattenSchema(schema, depth = 0) {
  if (!schema || typeof schema !== 'object' || depth > 3) return '';
  let text = '';
  if (schema.description) text += ' ' + schema.description;
  if (schema.default && typeof schema.default === 'string') text += ' ' + schema.default;
  if (schema.properties) {
    for (const val of Object.values(schema.properties)) {
      text += flattenSchema(val, depth + 1);
    }
  }
  if (schema.items) text += flattenSchema(schema.items, depth + 1);
  if (Array.isArray(schema.enum)) {
    for (const e of schema.enum) {
      if (typeof e === 'string') text += ' ' + e;
    }
  }
  return text;
}

// ── Main Scanner ─────────────────────────────────────────────

/**
 * Scan an array of MCP tool definitions for poisoning indicators.
 *
 * @param {Array<{name: string, description?: string, inputSchema?: object}>} tools
 *   Array of tool definitions to scan.
 * @param {object} [options]
 * @param {string} [options.server_name] - Name of the MCP server (for reporting)
 * @param {boolean} [options.include_info] - Include info-level findings (default: false)
 * @returns {{ findings: Array, summary: object }}
 */
export function scanTools(tools, options = {}) {
  const serverName = options.server_name || 'unknown';
  const includeInfo = options.include_info || false;

  // Input validation
  if (!Array.isArray(tools)) {
    return {
      findings: [],
      summary: {
        server_name: serverName,
        scan_timestamp: new Date().toISOString(),
        tools_scanned: 0,
        total_findings: 0,
        risk_level: 'unknown',
        error: 'Invalid input: tools must be an array',
        by_category: {},
      },
    };
  }

  if (tools.length === 0) {
    return {
      findings: [],
      summary: {
        server_name: serverName,
        scan_timestamp: new Date().toISOString(),
        tools_scanned: 0,
        total_findings: 0,
        risk_level: 'none',
        clean: true,
        by_category: {},
      },
    };
  }

  const allFindings = [];

  // Per-tool scans (categories 1, 2, 3, 6, 7, 8)
  for (const tool of tools) {
    const name = tool.name || '(unnamed)';
    const desc = tool.description || '';

    // Truncate extremely long descriptions for performance
    const scanDesc = desc.length > 50_000 ? desc.slice(0, 50_000) : desc;

    // Scan tool name
    if (name && name !== '(unnamed)') {
      allFindings.push(...detectHiddenUnicode(name, name, 'name'));
      allFindings.push(...detectHomoglyphs(name, name, 'name'));
    }

    // Scan description
    if (scanDesc) {
      allFindings.push(...detectHiddenUnicode(scanDesc, name, 'description'));
      allFindings.push(...detectInjectionPatterns(scanDesc, name, 'description'));
      allFindings.push(...detectObfuscatedPayloads(scanDesc, name, 'description'));
      allFindings.push(...detectHomoglyphs(scanDesc, name, 'description'));
      allFindings.push(...detectSuspiciousUrls(scanDesc, name, 'description'));
    }

    // Scan inputSchema (category 8)
    allFindings.push(...detectSchemaManipulation(tool));
  }

  // Multi-tool scans (categories 4, 5)
  allFindings.push(...detectExcessiveLength(tools));
  allFindings.push(...detectCrossToolManipulation(tools));

  // Filter info-level findings if not requested
  const findings = includeInfo
    ? allFindings
    : allFindings.filter(f => f.severity !== 'info');

  // Build summary
  const byCategory = {};
  const bySeverity = { critical: 0, high: 0, medium: 0, warning: 0, info: 0 };
  for (const f of findings) {
    byCategory[f.category] = (byCategory[f.category] || 0) + 1;
    bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
  }

  // Determine overall risk level
  let riskLevel = 'none';
  if (bySeverity.critical > 0) riskLevel = 'critical';
  else if (bySeverity.high > 0) riskLevel = 'high';
  else if (bySeverity.medium > 0) riskLevel = 'medium';
  else if (bySeverity.warning > 0) riskLevel = 'low';

  return {
    findings,
    summary: {
      server_name: serverName,
      scan_timestamp: new Date().toISOString(),
      tools_scanned: tools.length,
      total_findings: findings.length,
      risk_level: riskLevel,
      clean: findings.length === 0,
      by_severity: bySeverity,
      by_category: byCategory,
      disclaimer: 'This is a heuristic scanner detecting known patterns. It cannot detect novel semantic attacks. A clean scan does NOT guarantee safety.',
    },
  };
}

// ── Static Tool Definition Extractor ─────────────────────────

/**
 * Attempt to statically extract MCP tool definitions from source code files.
 * This is a best-effort heuristic — it cannot handle dynamic tool registration.
 *
 * @param {Array<{path: string, content: string}>} files - Source code files
 * @returns {Array<{name: string, description: string, inputSchema: object|null}>}
 */
export function extractToolDefinitions(files) {
  const tools = [];

  for (const file of files) {
    const content = file.content || '';

    // Pattern 1: JS/TS MCP SDK — tools array with { name, description, inputSchema }
    // Matches objects in a tools array with name and description fields
    const toolBlockRegex = /\{\s*name\s*:\s*['"`]([^'"`]+)['"`]\s*,\s*description\s*:\s*['"`]([\s\S]*?)['"`]\s*(?:,\s*inputSchema\s*:\s*(\{[\s\S]*?\})\s*)?\}/g;
    let match;
    while ((match = toolBlockRegex.exec(content)) !== null) {
      const name = match[1];
      const description = match[2];
      let inputSchema = null;
      if (match[3]) {
        try { inputSchema = JSON.parse(match[3].replace(/'/g, '"')); } catch {}
      }
      // Skip if this looks like a generic object (too short name, common keywords)
      if (name.length >= 2 && !['type', 'name', 'string', 'object'].includes(name)) {
        tools.push({ name, description, inputSchema, source_file: file.path });
      }
    }

    // Pattern 2: Python FastMCP — @mcp.tool() or @server.tool() decorators
    const pyToolRegex = /@(?:mcp|server|app)\.tool\(\)\s*(?:async\s+)?def\s+(\w+)\s*\([^)]*\)(?:\s*->.*?)?\s*:\s*\n\s*"""([\s\S]*?)"""/g;
    while ((match = pyToolRegex.exec(content)) !== null) {
      tools.push({
        name: match[1],
        description: match[2].trim(),
        inputSchema: null,
        source_file: file.path,
      });
    }

    // Pattern 3: Python Tool(name=..., description=...)
    const pyToolClassRegex = /Tool\s*\(\s*name\s*=\s*['"](\w+)['"]\s*,\s*description\s*=\s*['"]([^'"]*)['"]/g;
    while ((match = pyToolClassRegex.exec(content)) !== null) {
      tools.push({
        name: match[1],
        description: match[2],
        inputSchema: null,
        source_file: file.path,
      });
    }
  }

  // Deduplicate by name (keep first occurrence)
  const seen = new Set();
  return tools.filter(t => {
    if (seen.has(t.name)) return false;
    seen.add(t.name);
    return true;
  });
}
