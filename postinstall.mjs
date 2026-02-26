#!/usr/bin/env node
const g = '\x1b[32m', c = '\x1b[36m', d = '\x1b[2m', b = '\x1b[1m', r = '\x1b[0m';

console.log();
console.log(`  ${g}✔${r}  ${b}AgentAudit${r} installed!`);
console.log();
console.log(`  ${b}Get started:${r}`);
console.log(`    ${c}agentaudit discover${r}        Find your MCP servers + check security status`);
console.log(`    ${c}agentaudit setup${r}            Register for an API key ${d}(free)${r}`);
console.log(`    ${c}agentaudit scan <url>${r}       Quick static scan`);
console.log(`    ${c}agentaudit audit <url>${r}      Deep LLM-powered audit`);
console.log();
console.log(`  ${b}For deep audits,${r} set an LLM API key:`);
console.log(`    ${d}export ANTHROPIC_API_KEY=sk-ant-...${r}    ${d}# or OPENAI_API_KEY${r}`);
console.log();
console.log(`  ${b}Or use as MCP server${r} in Cursor/Claude ${d}(no API key needed)${r}:`);
console.log(`    ${d}{ "agentaudit": { "command": "npx", "args": ["-y", "agentaudit"] } }${r}`);
console.log();
