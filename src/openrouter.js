const API = 'https://openrouter.ai/api/v1';

async function request(url, options, timeout = 25000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  try { return await fetch(url, { ...options, signal: controller.signal }); }
  finally { clearTimeout(timer); }
}

async function selectFreeModel(apiKey) {
  const response = await request(`${API}/models`, { headers: { Authorization: `Bearer ${apiKey}` } });
  if (!response.ok) throw new Error(`OpenRouter models request failed (${response.status}).`);
  const { data = [] } = await response.json();
  const free = data.filter(m => m.id?.endsWith(':free') || (Number(m.pricing?.prompt) === 0 && Number(m.pricing?.completion) === 0));
  const preferred = free.filter(m => /qwen|llama|gemma|mistral|deepseek/i.test(m.id));
  const ranked = (preferred.length ? preferred : free).sort((a,b) => Number(b.context_length || 0) - Number(a.context_length || 0));
  if (!ranked.length) throw new Error('No free OpenRouter model is currently available. Try again later.');
  return ranked[0].id;
}

async function analyzeWithOpenRouter(apiKey, model, report) {
  const compact = { target: report.target, summary: report.summary, findings: report.findings.map(({severity,title,evidence,recommendation,url}) => ({severity,title,evidence,recommendation,url})) };
  const response = await request(`${API}/chat/completions`, { method: 'POST', headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json', 'HTTP-Referer': 'https://github.com/gochag421-beep/site-admin-panel', 'X-Title': 'Vexon Security Scanner' }, body: JSON.stringify({ model, temperature: 0.15, messages: [
    { role: 'system', content: 'You are a defensive web security reviewer. Analyze only the supplied passive scan findings. Never invent vulnerabilities, credentials, exploits, payloads, or CVEs. Reply in Greek with: executive summary, prioritized remediation plan, and verification checklist. Be concise and clearly label uncertainty.' },
    { role: 'user', content: JSON.stringify(compact) }
  ]}) });
  if (!response.ok) throw new Error(`OpenRouter analysis failed (${response.status}): ${(await response.text()).slice(0,240)}`);
  const json = await response.json();
  return { text: json.choices?.[0]?.message?.content || 'No analysis returned.' };
}

module.exports = { selectFreeModel, analyzeWithOpenRouter };
