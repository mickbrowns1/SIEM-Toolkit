'use client'

import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { Shield, BarChart2, Zap, Home } from 'lucide-react'
import clsx from 'clsx'

const NAV = [
  { href: '/', label: 'Overview', icon: Home },
  { href: '/coverage', label: 'Parser Coverage', icon: Shield },
  { href: '/ingest', label: 'Ingest Dashboard', icon: BarChart2 },
  { href: '/onboarding', label: 'Onboarding', icon: Zap },
]

export default function Sidebar() {
  const path = usePathname()
  return (
    <aside className="w-56 shrink-0 bg-gray-900 border-r border-gray-800 flex flex-col">
      <div className="p-4 border-b border-gray-800">
        <div className="flex items-center gap-2">
          <div className="w-6 h-6 rounded bg-purple-600 flex items-center justify-center text-xs font-bold">S1</div>
          <span className="font-semibold text-sm text-white">SIEM Toolkit</span>
        </div>
        <p className="text-xs text-gray-500 mt-1">demo.sentinelone.net</p>
      </div>
      <nav className="flex-1 p-3 space-y-1">
        {NAV.map(({ href, label, icon: Icon }) => (
          <Link
            key={href}
            href={href}
            className={clsx(
              'flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-colors',
              path === href
                ? 'bg-purple-700 text-white'
                : 'text-gray-400 hover:bg-gray-800 hover:text-gray-100'
            )}
          >
            <Icon size={15} />
            {label}
          </Link>
        ))}
      </nav>
    </aside>
  )
}
