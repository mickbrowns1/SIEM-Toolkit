import type { Metadata } from 'next'
import './globals.css'
import Sidebar from '@/components/Sidebar'
import QueryProvider from '@/components/QueryProvider'

export const metadata: Metadata = {
  title: 'SIEM Toolkit',
  description: 'SentinelOne AI-SIEM Engineering Toolkit',
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="font-sans bg-gray-950 text-gray-100 h-screen flex overflow-hidden">
        <QueryProvider>
          <Sidebar />
          <main className="flex-1 overflow-auto">{children}</main>
        </QueryProvider>
      </body>
    </html>
  )
}
