'use client'

import { useState, useRef } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api'
import clsx from 'clsx'

type FieldDetail = {
  in_parser: boolean
  parser_name: string | null
  rule_count: number
  rules: { rule: string; type: string }[]
  status: 'covered' | 'unused' | 'missing_parser'
}

type CoverageMap = {
  summary: {
    total_parser_fields: number
    total_rule_fields: number
    covered: number
    parsed_but_unused: number
    rules_missing_parser: number
  }
  fields: Record<string, FieldDetail>
}

const STATUS_STYLE = {
  covered: 'bg-emerald-900/50 text-emerald-300 border-emerald-700',
  unused: 'bg-yellow-900/50 text-yellow-300 border-yellow-700',
  missing_parser: 'bg-red-900/50 text-red-300 border-red-700',
}

const STATUS_LABEL = {
  covered: 'Covered',
  unused: 'Unused (reduce candidate)',
  missing_parser: 'Missing parser',
}

export default function CoveragePage() {
  const qc = useQueryClient()
  const sigmaRef = useRef<HTMLInputElement>(null)
  const parserRef = useRef<HTMLInputElement>(null)
  const [filter, setFilter] = useState<'all' | 'covered' | 'unused' | 'missing_parser'>('all')
  const [err, setErr] = useState('')

  const { data, isLoading } = useQuery<CoverageMap>({
    queryKey: ['coverage-map'],
    queryFn: () => api.get('/api/coverage/map'),
  })

  const loadStar = useMutation({
    mutationFn: () => api.post('/api/coverage/load-star-rules', {}),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['coverage-map'] }),
    onError: (e: Error) => setErr(e.message),
  })

  const uploadSigma = useMutation({
    mutationFn: async (files: FileList) => {
      const form = new FormData()
      Array.from(files).forEach((f) => form.append('files', f))
      return api.postForm('/api/coverage/upload-sigma', form)
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['coverage-map'] }),
    onError: (e: Error) => setErr(e.message),
  })

  const uploadParser = useMutation({
    mutationFn: async (file: File) => {
      const form = new FormData()
      form.append('file', file)
      return api.postForm('/api/coverage/upload-parser', form)
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['coverage-map'] }),
    onError: (e: Error) => setErr(e.message),
  })

  const reset = useMutation({
    mutationFn: () => api.get('/api/coverage/reset'),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['coverage-map'] }),
  })

  const fields = data
    ? Object.entries(data.fields).filter(
        ([, d]) => filter === 'all' || d.status === filter
      )
    : []

  const busy = loadStar.isPending || uploadSigma.isPending || uploadParser.isPending

  return (
    <div className="p-8 max-w-6xl">
      <div className="flex items-start justify-between mb-6">
        <div>
          <h1 className="text-xl font-bold text-white">Parser Coverage Map</h1>
          <p className="text-sm text-gray-400 mt-1">
            Cross-reference SDL parser fields against STAR / Sigma rule fields
          </p>
        </div>
        <div className="flex gap-2 flex-wrap justify-end">
          <button
            onClick={() => loadStar.mutate()}
            disabled={busy}
            className="px-3 py-1.5 text-sm bg-purple-700 hover:bg-purple-600 disabled:opacity-50 rounded-lg text-white"
          >
            {loadStar.isPending ? 'Loading…' : 'Load STAR Rules'}
          </button>
          <button
            onClick={() => sigmaRef.current?.click()}
            disabled={busy}
            className="px-3 py-1.5 text-sm bg-gray-700 hover:bg-gray-600 disabled:opacity-50 rounded-lg text-white"
          >
            Upload Sigma Rules
          </button>
          <button
            onClick={() => parserRef.current?.click()}
            disabled={busy}
            className="px-3 py-1.5 text-sm bg-gray-700 hover:bg-gray-600 disabled:opacity-50 rounded-lg text-white"
          >
            Upload Parser
          </button>
          <button
            onClick={() => reset.mutate()}
            disabled={busy}
            className="px-3 py-1.5 text-sm bg-red-900/60 hover:bg-red-800 disabled:opacity-50 rounded-lg text-red-300"
          >
            Reset
          </button>
        </div>
      </div>

      <input
        ref={sigmaRef}
        type="file"
        accept=".yml,.yaml"
        multiple
        className="hidden"
        onChange={(e) => e.target.files && uploadSigma.mutate(e.target.files)}
      />
      <input
        ref={parserRef}
        type="file"
        accept=".json"
        className="hidden"
        onChange={(e) => e.target.files?.[0] && uploadParser.mutate(e.target.files[0])}
      />

      {err && (
        <div className="mb-4 p-3 bg-red-900/40 border border-red-700 rounded-lg text-sm text-red-300">
          {err}
        </div>
      )}

      {data && (
        <div className="grid grid-cols-5 gap-3 mb-6">
          {[
            { label: 'Parser Fields', value: data.summary.total_parser_fields, color: 'text-gray-200' },
            { label: 'Rule Fields', value: data.summary.total_rule_fields, color: 'text-gray-200' },
            { label: 'Covered', value: data.summary.covered, color: 'text-emerald-400' },
            { label: 'Parsed Unused', value: data.summary.parsed_but_unused, color: 'text-yellow-400' },
            { label: 'Missing Parser', value: data.summary.rules_missing_parser, color: 'text-red-400' },
          ].map(({ label, value, color }) => (
            <div key={label} className="bg-gray-900 border border-gray-800 rounded-lg p-4 text-center">
              <div className={`text-2xl font-bold ${color}`}>{value}</div>
              <div className="text-xs text-gray-500 mt-1">{label}</div>
            </div>
          ))}
        </div>
      )}

      <div className="flex gap-2 mb-4">
        {(['all', 'covered', 'unused', 'missing_parser'] as const).map((f) => (
          <button
            key={f}
            onClick={() => setFilter(f)}
            className={clsx(
              'px-3 py-1 text-xs rounded-full border transition-colors',
              filter === f
                ? 'bg-purple-700 border-purple-600 text-white'
                : 'border-gray-700 text-gray-400 hover:border-gray-500'
            )}
          >
            {f === 'all' ? 'All' : STATUS_LABEL[f]}
          </button>
        ))}
      </div>

      {isLoading ? (
        <div className="text-gray-500 text-sm">Loading…</div>
      ) : fields.length === 0 ? (
        <div className="text-gray-600 text-sm">
          {data ? 'No fields match this filter.' : 'Load STAR rules or upload parsers to begin.'}
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-gray-500 border-b border-gray-800">
                <th className="pb-2 pr-4 font-medium">Field</th>
                <th className="pb-2 pr-4 font-medium">Status</th>
                <th className="pb-2 pr-4 font-medium">Parser</th>
                <th className="pb-2 font-medium">Rules using it</th>
              </tr>
            </thead>
            <tbody>
              {fields.map(([field, detail]) => (
                <tr key={field} className="border-b border-gray-800/50 hover:bg-gray-900/30">
                  <td className="py-2 pr-4 font-mono text-xs text-gray-200">{field}</td>
                  <td className="py-2 pr-4">
                    <span
                      className={clsx(
                        'px-2 py-0.5 rounded text-xs border',
                        STATUS_STYLE[detail.status]
                      )}
                    >
                      {STATUS_LABEL[detail.status]}
                    </span>
                  </td>
                  <td className="py-2 pr-4 text-xs text-gray-400">{detail.parser_name ?? '—'}</td>
                  <td className="py-2 text-xs text-gray-400">
                    {detail.rule_count > 0
                      ? detail.rules.map((r) => r.rule).join(', ')
                      : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
