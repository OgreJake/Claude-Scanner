import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Download } from 'lucide-react'
import { listFindings, updateFinding, downloadFindingsCsv } from '../lib/api'
import type { Finding } from '../types'
import SeverityBadge from '../components/SeverityBadge'
import { format } from 'date-fns'

export default function Findings() {
  const qc = useQueryClient()
  const [severity, setSeverity] = useState('')
  const [findingStatus, setFindingStatus] = useState('open')
  const [page, setPage] = useState(1)

  const { data, isLoading } = useQuery<Finding[]>({
    queryKey: ['findings', { severity, findingStatus, page }],
    queryFn: () =>
      listFindings({
        severity: severity || undefined,
        status: findingStatus || undefined,
        page,
        page_size: 100,
      }).then((r) => r.data),
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, status }: { id: string; status: string }) =>
      updateFinding(id, { status }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['findings'] }),
  })

  async function handleExportCsv() {
    const res = await downloadFindingsCsv({
      severity: severity || undefined,
      status: findingStatus || undefined,
    })
    const url = URL.createObjectURL(new Blob([res.data], { type: 'text/csv' }))
    const a = document.createElement('a')
    a.href = url
    a.download = 'findings.csv'
    a.click()
  }

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Findings</h1>
          <p className="text-sm text-gray-500 mt-0.5">All vulnerability findings across the fleet</p>
        </div>
        <button
          onClick={handleExportCsv}
          className="flex items-center gap-2 border border-gray-200 px-4 py-2 rounded-lg text-sm
                     hover:bg-gray-50 text-gray-700 transition-colors"
        >
          <Download size={15} /> Export CSV
        </button>
      </div>

      {/* Filters */}
      <div className="flex gap-3">
        <select
          value={severity}
          onChange={(e) => { setSeverity(e.target.value); setPage(1) }}
          className="border border-gray-200 rounded-lg px-3 py-1.5 text-sm
                     focus:outline-none focus:ring-2 focus:ring-brand-500"
        >
          <option value="">All Severities</option>
          {['critical', 'high', 'medium', 'low'].map((s) => (
            <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>
          ))}
        </select>
        <select
          value={findingStatus}
          onChange={(e) => { setFindingStatus(e.target.value); setPage(1) }}
          className="border border-gray-200 rounded-lg px-3 py-1.5 text-sm
                     focus:outline-none focus:ring-2 focus:ring-brand-500"
        >
          <option value="">All Statuses</option>
          {['open', 'acknowledged', 'false_positive', 'resolved'].map((s) => (
            <option key={s} value={s}>{s.replace('_', ' ')}</option>
          ))}
        </select>
      </div>

      <div className="bg-white rounded-xl border border-gray-200 shadow-sm overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-xs text-gray-500 bg-gray-50 border-b border-gray-100">
              {['CVE ID', 'Component', 'Version', 'Severity', 'CVSS', 'EPSS', 'Status', 'First Seen', 'Actions'].map((h) => (
                <th key={h} className="px-4 py-3 text-left font-medium">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-100">
            {isLoading && (
              <tr><td colSpan={9} className="px-4 py-8 text-center text-gray-400">Loading…</td></tr>
            )}
            {data?.map((f) => (
              <tr key={f.id} className="hover:bg-gray-50">
                <td className="px-4 py-3 font-mono text-blue-700">{f.vulnerability_id}</td>
                <td className="px-4 py-3 text-gray-700">{f.affected_component ?? '—'}</td>
                <td className="px-4 py-3 font-mono text-xs text-gray-500">{f.affected_version ?? '—'}</td>
                <td className="px-4 py-3"><SeverityBadge severity={f.severity} /></td>
                <td className="px-4 py-3 tabular-nums">{f.cvss_score?.toFixed(1) ?? '—'}</td>
                <td className="px-4 py-3 tabular-nums font-medium text-orange-700">
                  {f.epss_score != null ? (f.epss_score * 100).toFixed(2) + '%' : '—'}
                </td>
                <td className="px-4 py-3">
                  <span className="text-xs text-gray-600 capitalize">{f.status.replace('_', ' ')}</span>
                </td>
                <td className="px-4 py-3 text-xs text-gray-500">
                  {format(new Date(f.first_seen), 'MMM d, yyyy')}
                </td>
                <td className="px-4 py-3">
                  <select
                    value={f.status}
                    onChange={(e) => updateMutation.mutate({ id: f.id, status: e.target.value })}
                    className="text-xs border border-gray-200 rounded px-1.5 py-1
                               focus:outline-none focus:ring-1 focus:ring-brand-500"
                  >
                    {['open', 'acknowledged', 'false_positive', 'resolved'].map((s) => (
                      <option key={s} value={s}>{s.replace('_', ' ')}</option>
                    ))}
                  </select>
                </td>
              </tr>
            ))}
            {!isLoading && !data?.length && (
              <tr>
                <td colSpan={9} className="px-4 py-10 text-center text-gray-400">
                  No findings match your filters.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      <div className="flex justify-end gap-2">
        <button
          disabled={page === 1}
          onClick={() => setPage((p) => p - 1)}
          className="px-3 py-1.5 text-sm border border-gray-200 rounded-lg hover:bg-gray-50 disabled:opacity-40"
        >
          Previous
        </button>
        <span className="px-3 py-1.5 text-sm text-gray-500">Page {page}</span>
        <button
          disabled={(data?.length ?? 0) < 100}
          onClick={() => setPage((p) => p + 1)}
          className="px-3 py-1.5 text-sm border border-gray-200 rounded-lg hover:bg-gray-50 disabled:opacity-40"
        >
          Next
        </button>
      </div>
    </div>
  )
}
