import { Shield, Brain, Scale, Lock, Eye, Zap, Terminal, Cpu, Database, Network, Github, Linkedin, Layers, Activity, ChevronRight } from 'lucide-react'

const capabilities = [
  {
    icon: Scale,
    title: '70 / 30 Hybrid Scoring',
    desc: 'Deterministic rules contribute 70% of the final trust score. AI advisory provides the remaining 30% — only after passing a 4-stage calibration pipeline that limits overconfidence.',
    tag: 'CORE',
  },
  {
    icon: Brain,
    title: 'AI as Advisor, Not Judge',
    desc: 'The AI model (Gemini, OpenAI, Anthropic, or Grok) is treated as one signal among many — never the final word. A raw 99% AI confidence becomes ~18% after calibration.',
    tag: 'AI',
  },
  {
    icon: Lock,
    title: 'Anti-Hallucination Layers',
    desc: 'Five defense layers prevent AI fabrication: input sanitization, prompt fencing, JSON schema validation, range clamping, and evidence cross-referencing against observed facts.',
    tag: 'SECURITY',
  },
  {
    icon: Eye,
    title: 'Visual Clone Detection',
    desc: 'Perceptual hash (pHash) screenshot comparison detects brand impersonation — catching sophisticated clone sites that text analysis misses.',
    tag: 'VISION',
  },
  {
    icon: Zap,
    title: 'Zero-Day Threat Detection',
    desc: 'Composite anomaly scoring evaluates unusual patterns across multiple signals — catching threats too new for any blocklist without relying on known IOCs.',
    tag: 'ZERODAY',
  },
  {
    icon: Shield,
    title: 'Full Transparency',
    desc: 'Every analysis includes complete audit trail: rule breakdown, AI calibration trace, evidence list, signal map, and human-readable explanation. Nothing is a black box.',
    tag: 'AUDIT',
  },
]

const techStack = [
  { icon: Cpu, label: 'FastAPI + Python 3.9', desc: 'High-performance async backend' },
  { icon: Terminal, label: 'React 19 + TypeScript', desc: 'Type-safe modern frontend' },
  { icon: Database, label: 'SQLite + Pydantic v2', desc: 'Lightweight data layer' },
  { icon: Network, label: 'Playwright Sandbox', desc: 'Headless browser crawling' },
  { icon: Layers, label: 'Multi-Provider AI', desc: 'Gemini, OpenAI, Anthropic, Grok' },
  { icon: Activity, label: '15+ Analysis Engines', desc: 'Domain, header, brand, behavioral' },
]

const stats = [
  { value: '15+', label: 'Analysis Engines' },
  { value: '70/30', label: 'Rule/AI Split' },
  { value: '5', label: 'Anti-Hallucination Layers' },
  { value: '4', label: 'AI Providers Supported' },
]

export default function AboutPage() {
  return (
    <div className="max-w-5xl mx-auto px-4 py-10 animate-fade-in">
      {/* Hero */}
      <div className="text-center mb-12">
        <div className="inline-flex items-center justify-center w-14 h-14 rounded-lg border border-[#00ff41]/20 bg-[#00ff41]/5 mb-5 animate-pulse-glow">
          <Shield className="w-7 h-7 text-[#00ff41]" />
        </div>
        <h1 className="font-mono text-2xl sm:text-3xl font-bold text-white mb-3 tracking-tight">
          <span className="text-[#00ff41] glow-green">TRUSTLENS</span>{' '}
          <span className="text-[#00ffff] glow-cyan">AI</span>
        </h1>
        <p className="font-mono text-xs text-[#484f58] max-w-2xl mx-auto leading-relaxed">
          An enterprise-grade, explainable URL trust intelligence engine that combines
          deterministic rule-based analysis with AI reasoning — while keeping AI on a
          tight leash through multi-layered calibration and anti-hallucination safeguards.
        </p>
      </div>

      {/* Stats Bar */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-10">
        {stats.map(s => (
          <div key={s.label} className="terminal-card text-center p-4">
            <p className="font-mono text-xl font-bold text-[#00ff41] glow-green mb-1">{s.value}</p>
            <p className="font-mono text-[10px] text-[#484f58] uppercase tracking-wider">{s.label}</p>
          </div>
        ))}
      </div>

      {/* Capabilities */}
      <div className="mb-10">
        <h2 className="font-mono text-xs font-semibold text-[#484f58] uppercase tracking-widest mb-4 flex items-center gap-2">
          <span className="text-[#00ff41]/40">{'>'}</span> Core Capabilities
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {capabilities.map(({ icon: Icon, title, desc, tag }, i) => (
            <div
              key={title}
              className="terminal-card group hover:border-[#00ff41]/15 transition-all animate-fade-in p-4"
              style={{ animationDelay: `${i * 80}ms`, opacity: 0 }}
            >
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-2.5">
                  <div className="w-7 h-7 rounded border border-[#1b2838] bg-[#0a0e17] flex items-center justify-center group-hover:border-[#00ffff]/20 transition">
                    <Icon className="w-3.5 h-3.5 text-[#00ffff]" />
                  </div>
                  <h3 className="font-mono text-xs font-semibold text-[#c9d1d9]">{title}</h3>
                </div>
                <span className="font-mono text-[8px] text-[#00ff41]/30 border border-[#00ff41]/10 rounded px-1.5 py-0.5 tracking-wider">
                  {tag}
                </span>
              </div>
              <p className="font-mono text-[10px] text-[#484f58] leading-relaxed">{desc}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Architecture / Tech Stack */}
      <div className="mb-10">
        <h2 className="font-mono text-xs font-semibold text-[#484f58] uppercase tracking-widest mb-4 flex items-center gap-2">
          <span className="text-[#00ff41]/40">{'>'}</span> Technology Stack
        </h2>
        <div className="terminal-card">
          <div className="terminal-card-header">
            <span>system://architecture</span>
          </div>
          <div className="p-4 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
            {techStack.map(({ icon: Icon, label, desc }) => (
              <div key={label} className="flex items-start gap-3 p-2.5 rounded border border-[#1b2838] bg-[#0a0e17]/60 hover:border-[#00ffff]/10 transition">
                <Icon className="w-4 h-4 text-[#00ffff] mt-0.5 shrink-0" />
                <div>
                  <p className="font-mono text-[11px] font-medium text-[#c9d1d9]">{label}</p>
                  <p className="font-mono text-[9px] text-[#484f58]">{desc}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* How It Works - Pipeline */}
      <div className="mb-10">
        <h2 className="font-mono text-xs font-semibold text-[#484f58] uppercase tracking-widest mb-4 flex items-center gap-2">
          <span className="text-[#00ff41]/40">{'>'}</span> Analysis Pipeline
        </h2>
        <div className="terminal-card">
          <div className="terminal-card-header">
            <span>pipeline://flow</span>
          </div>
          <div className="p-4">
            <div className="flex flex-wrap items-center gap-2 font-mono text-[10px]">
              {['URL Input', 'Browser Crawl', 'Content Extraction', 'Rule Engine', 'Brand Detection', 'AI Analysis', 'Calibration', 'Score Fusion', 'Report'].map((step, i) => (
                <div key={step} className="flex items-center gap-2">
                  <span className="px-2.5 py-1 rounded border border-[#1b2838] bg-[#0a0e17] text-[#c9d1d9] hover:border-[#00ff41]/20 transition cursor-default">
                    {step}
                  </span>
                  {i < 8 && <ChevronRight className="w-3 h-3 text-[#00ff41]/30" />}
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* License */}
      <div className="mb-12">
        <div className="terminal-card max-w-2xl mx-auto">
          <div className="terminal-card-header">
            <span>license://open-source</span>
          </div>
          <div className="p-5">
            <div className="flex items-start gap-4">
              <div className="w-9 h-9 rounded border border-[#00ff41]/15 bg-[#00ff41]/5 flex items-center justify-center shrink-0 mt-0.5">
                <Scale className="w-4 h-4 text-[#00ff41]" />
              </div>
              <div>
                <h3 className="font-mono text-sm font-bold text-[#c9d1d9] mb-1">MIT License</h3>
                <p className="font-mono text-[10px] text-[#484f58] leading-relaxed mb-3">
                  Copyright © {new Date().getFullYear()} TrustLens Contributors
                </p>
                <p className="font-mono text-[10px] text-[#484f58]/80 leading-relaxed">
                  Permission is hereby granted, free of charge, to any person obtaining a copy of this software
                  and associated documentation files, to deal in the Software without restriction, including
                  without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense,
                  and/or sell copies of the Software, subject to the conditions in the{' '}
                  <a
                    href="https://github.com/abhishekayu/TrustLens/blob/main/LICENSE"
                    target="_blank"
                    rel="noreferrer"
                    className="text-[#00ffff]/70 hover:text-[#00ffff] underline underline-offset-2 transition"
                  >
                    full license
                  </a>.
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Developer Credit */}
      <div className="border-t border-[#1b2838] pt-8 pb-4">
        <div className="terminal-card max-w-md mx-auto">
          <div className="terminal-card-header">
            <span>developer://info</span>
          </div>
          <div className="p-5 text-center">
            <p className="font-mono text-[10px] text-[#484f58] uppercase tracking-widest mb-2">
              Designed & Developed by
            </p>
            <h3 className="font-mono text-lg font-bold text-[#00ff41] glow-green mb-4">
              Abhishek Verma
            </h3>
            <div className="flex items-center justify-center gap-4">
              <a
                href="https://github.com/abhishekayu"
                target="_blank"
                rel="noreferrer"
                className="flex items-center gap-2 px-4 py-2 rounded border border-[#1b2838] bg-[#0a0e17] hover:border-[#00ff41]/25 hover:bg-[#00ff41]/5 transition font-mono text-[11px] text-[#484f58] hover:text-[#00ff41] group"
              >
                <Github className="w-4 h-4 group-hover:text-[#00ff41] transition" />
                <span>GitHub</span>
              </a>
              <a
                href="https://linkedin.com/in/abhishekayu"
                target="_blank"
                rel="noreferrer"
                className="flex items-center gap-2 px-4 py-2 rounded border border-[#1b2838] bg-[#0a0e17] hover:border-[#00ffff]/25 hover:bg-[#00ffff]/5 transition font-mono text-[11px] text-[#484f58] hover:text-[#00ffff] group"
              >
                <Linkedin className="w-4 h-4 group-hover:text-[#00ffff] transition" />
                <span>LinkedIn</span>
              </a>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
