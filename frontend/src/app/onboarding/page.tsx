import { Zap, MessageSquare, FileText, Code2 } from 'lucide-react'

const STEPS = [
  {
    icon: FileText,
    title: '1. Grab a log sample',
    desc: 'Copy 10–50 representative lines from the new log source. Include edge cases — errors, different event types, varying field presence.',
  },
  {
    icon: MessageSquare,
    title: '2. Paste into Claude Code',
    desc: 'Open Claude Code and say: "Onboard this log source for SentinelOne SDL" then paste the sample. Mention the source type if known (e.g. "Palo Alto firewall").',
  },
  {
    icon: Code2,
    title: '3. Get your artefacts',
    desc: 'Claude returns an SDL parser (augmented-JSON), field mappings to the SDL schema, starter STAR detection rules, and parser test assertions.',
  },
  {
    icon: Zap,
    title: '4. Deploy',
    desc: 'Drop the parser JSON into your /logParsers/ path. Paste the STAR rules into the AI-SIEM rule editor. Run the test assertions to validate extraction.',
  },
]

const PROMPT = `Onboard this log source for SentinelOne SDL. Please generate:
1. An SDL parser skeleton in augmented-JSON format (/logParsers/ format)
2. Field mappings from raw fields to the SDL common schema
3. 2–3 starter STAR detection rules for common threats from this source type
4. 5 parser test assertions (input line → expected field → expected value)

Log source: [describe source, e.g. "Palo Alto PAN-OS firewall"]

Raw log sample:
[paste your log lines here]`

export default function OnboardingPage() {
  return (
    <div className="p-8 max-w-3xl">
      <div className="mb-8">
        <h1 className="text-xl font-bold text-white">Onboarding Accelerator</h1>
        <p className="text-sm text-gray-400 mt-1">
          Use Claude Code directly — no API key required
        </p>
      </div>

      <div className="space-y-4 mb-8">
        {STEPS.map(({ icon: Icon, title, desc }) => (
          <div key={title} className="flex gap-4 bg-gray-900 border border-gray-800 rounded-xl p-4">
            <div className="w-8 h-8 shrink-0 rounded-lg bg-purple-900/60 flex items-center justify-center mt-0.5">
              <Icon size={15} className="text-purple-300" />
            </div>
            <div>
              <div className="text-sm font-medium text-white">{title}</div>
              <div className="text-sm text-gray-400 mt-1">{desc}</div>
            </div>
          </div>
        ))}
      </div>

      <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
        <div className="px-4 py-2 border-b border-gray-800 flex items-center justify-between">
          <span className="text-xs font-medium text-gray-400">Copy this prompt template</span>
          <CopyButton text={PROMPT} />
        </div>
        <pre className="p-4 text-xs text-gray-300 font-mono leading-relaxed whitespace-pre-wrap">{PROMPT}</pre>
      </div>
    </div>
  )
}

function CopyButton({ text }: { text: string }) {
  'use client'
  return <_CopyButton text={text} />
}

// Split to keep the page a server component with one small client island
import _CopyButton from './_CopyButton'
