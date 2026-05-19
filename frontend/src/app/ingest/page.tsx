'use client'

import { useState } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid,
} from 'recharts'
import { api } from '@/lib/api'

type SourceRow = { 'src.name': string; events: number }
type DayRow = { date: string; events: number }

export default function IngestPage() {
  const [days, setDays] = useState(7)
  const [simSource, setSimSource] = useState('')
  const [simEventType, setSimEventType] = useState('')
  const [simResult, setSimResult] = useState<Record<string, unknown> | null>(null)
  const [simErr, setSimErr] = useState('')

  const sources = useQuery<{ data: SourceRow[] }>({
    queryKey: ['top-sources', days],
    queryFn: () => api.get(`/api/ingest/top-sources?days=${days}`),
  })

  const daily = useQuery<DayRow[]>({
    queryKey: ['daily-volume', days],
    queryFn: () => api.get(`/api/ingest/daily-volume?days=${days}`),
  })

  const simulate = useMutation({
    mutationFn: () =>
      api.post<Record<string, unknown>>('/api/ingest/simulate-filter', {
        source: simSource,
        event_type: simEventType,
        days,
        gb_per_million_events: 0.5,
      }),
    onSuccess: (data) => { setSimResult(data); setSimErr('') },
    onError: (e: Error) => setSimErr(e.message),
  })

  const chartData = (sources.data?.data ?? []).slice(0, 15).map((r) => ({
    name: r['src.name'] ?? 'unknown',
    events: r.events ?? 0,
  }))

  return (
    <div className="p-8 max-w-6xl">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-xl font-bold text-white">Ingest Dashboard</h1>
          <p className="text-sm text-gray-400 mt-1">Event volume · cost projection · filter simulator</p>
        </div>
        <div className="flex gap-2">
          {[7, 14, 30].map((d) => (
            <button
              key={d}
              onClick={() => setDays(d)}
              className={`px-3 py-1.5 text-xs rounded-lg border transition-colors ${
                days === d
                  ? 'bg-purple-700 border-purple-600 text-white'
                  : 'border-gray-700 text-gray-400 hover:border-gray-500'
              }`}
            >
              {d}d
            </button>
          ))}
        </div>
      </div>

      {/* Daily volume chart */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl p-5 mb-5">
        <h2 className="text-sm font-medium text-gray-300 mb-4">Daily Event Volume</h2>
        {daily.isLoading ? (
          <div className="text-gray-600 text-sm h-32 flex items-center">Loading…</div>
        ) : (
          <ResponsiveContainer width="100%" height={160}>
            <BarChart data={daily.data ?? []}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
              <XAxis dataKey="date" tick={{ fontSize: 10, fill: '#6b7280' }} />
              <YAxis tick={{ fontSize: 10, fill: '#6b7280' }} />
              <Tooltip
                contentStyle={{ background: '#111827', border: '1px solid #374151', fontSize: 12 }}
                labelStyle={{ color: '#d1d5db' }}
              />
              <Bar dataKey="events" fill="#7c3aed" radius={[3, 3, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        )}
      </div>

      {/* Top sources table */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl p-5 mb-5">
        <h2 className="text-sm font-medium text-gray-300 mb-4">Top Sources — last {days}d</h2>
        {sources.isLoading ? (
          <div className="text-gray-600 text-sm">Loading…</div>
        ) : sources.isError ? (
          <div className="text-red-400 text-sm">{String(sources.error)}</div>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-gray-500 border-b border-gray-800">
                <th className="pb-2 font-medium">Source</th>
                <th className="pb-2 font-medium text-right">Events</th>
                <th className="pb-2 font-medium text-right">Est. GB</th>
              </tr>
            </thead>
            <tbody>
              {chartData.map((row) => (
                <tr key={row.name} className="border-b border-gray-800/50">
                  <td className="py-2 font-mono text-xs text-gray-200">{row.name}</td>
                  <td className="py-2 text-right text-gray-300">{row.events.toLocaleString()}</td>
                  <td className="py-2 text-right text-gray-400">
                    {(row.events / 1_000_000 * 0.5).toFixed(3)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Filter simulator */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
        <h2 className="text-sm font-medium text-gray-300 mb-4">Filter Simulator</h2>
        <p className="text-xs text-gray-500 mb-4">
          Estimate events and GB eliminated by dropping a source + event type combination.
        </p>
        <div className="flex gap-3 flex-wrap mb-4">
          <input
            value={simSource}
            onChange={(e) => setSimSource(e.target.value)}
            placeholder="Source name (optional)"
            className="flex-1 min-w-48 bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-200 placeholder-gray-600 focus:outline-none focus:border-purple-600"
          />
          <input
            value={simEventType}
            onChange={(e) => setSimEventType(e.target.value)}
            placeholder="Event type (optional)"
            className="flex-1 min-w-48 bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-200 placeholder-gray-600 focus:outline-none focus:border-purple-600"
          />
          <button
            onClick={() => simulate.mutate()}
            disabled={simulate.isPending || (!simSource && !simEventType)}
            className="px-4 py-2 text-sm bg-purple-700 hover:bg-purple-600 disabled:opacity-50 rounded-lg text-white"
          >
            {simulate.isPending ? 'Running…' : 'Simulate'}
          </button>
        </div>
        {simErr && <p className="text-red-400 text-sm">{simErr}</p>}
        {simResult && (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {[
              { label: 'Matched Events', value: String(simResult.matched_events ?? 0) },
              { label: `Est. GB (${days}d)`, value: String(simResult.estimated_gb_period ?? 0) },
              { label: 'Projected Monthly Events', value: String(simResult.projected_monthly_events ?? 0) },
              { label: 'Projected Monthly GB', value: String(simResult.projected_monthly_gb ?? 0) },
            ].map(({ label, value }) => (
              <div key={label} className="bg-gray-800 rounded-lg p-3 text-center">
                <div className="text-lg font-bold text-purple-300">{value}</div>
                <div className="text-xs text-gray-500 mt-1">{label}</div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
