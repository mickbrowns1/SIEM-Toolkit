import { Shield, BarChart2, Zap } from 'lucide-react'
import Link from 'next/link'

const CARDS = [
  {
    href: '/coverage',
    icon: Shield,
    title: 'Parser Coverage Map',
    desc: 'Cross-reference SDL parser output fields against STAR and Sigma rule fields. Surface parsed-but-unused fields as reduction candidates.',
    cta: 'Open Coverage Map',
    color: 'from-purple-700 to-purple-900',
  },
  {
    href: '/ingest',
    icon: BarChart2,
    title: 'Ingest Dashboard',
    desc: 'Visualize event volume by source and type. Project monthly GB costs and simulate the impact of exclusion filters before applying them.',
    cta: 'Open Dashboard',
    color: 'from-blue-700 to-blue-900',
  },
  {
    href: '/onboarding',
    icon: Zap,
    title: 'Onboarding Accelerator',
    desc: 'Step-by-step guide for onboarding a new log source using Claude Code directly — no API key required.',
    cta: 'View Onboarding Guide',
    color: 'from-emerald-700 to-emerald-900',
  },
]

export default function Home() {
  return (
    <div className="p-8 max-w-5xl">
      <div className="mb-8">
        <h1 className="text-2xl font-bold text-white">SIEM Engineering Toolkit</h1>
        <p className="text-gray-400 mt-1">SentinelOne AI-SIEM · demo.sentinelone.net</p>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
        {CARDS.map(({ href, icon: Icon, title, desc, cta, color }) => (
          <div key={href} className="bg-gray-900 border border-gray-800 rounded-xl p-6 flex flex-col gap-4">
            <div className={`w-10 h-10 rounded-lg bg-gradient-to-br ${color} flex items-center justify-center`}>
              <Icon size={20} className="text-white" />
            </div>
            <div>
              <h2 className="font-semibold text-white">{title}</h2>
              <p className="text-sm text-gray-400 mt-1 leading-relaxed">{desc}</p>
            </div>
            <Link
              href={href}
              className="mt-auto text-sm text-purple-400 hover:text-purple-300 font-medium"
            >
              {cta} →
            </Link>
          </div>
        ))}
      </div>
    </div>
  )
}
