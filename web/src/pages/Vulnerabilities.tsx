import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { listVulnerabilities } from '../lib/api'
import type { Vulnerability } from '../types'
import SeverityBadge from '../components/SeverityBadge'

export default function Vulnerabilities() {
  const [search, setSearch] = useState('')
  const [severity, setSeverity] = useState('')
  const [page, setPage] = useState(1)

  const { data, isLoading } = useQuery<Vulnerability[]>({
    queryKey: ['vulnerabilities', { search, severity, page }],
    queryFn: () =>
      listVulnerabilities({
        search: search || undefined,
        severity: severity || undefined,
        page,
        page_size: 50,
      }).then((r) => r.data),
  })

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Vulnerabilities</h1>
        <p className="text-sm text-gray-500 mt-0.5">CVE / OSV knowledge base</p>
      </div>

      {/* Filters */}
      <div className="flex gap-3">
        <input
          type="text"
          placeholder="Search CVE ID or description…"
          value={search}
          onChange={(e) => { setSearch(e.target.value); setPage(1) }}
          className="border border-gray-200 rounded-lg px-3 py-1.5 text-sm w-72
                     focus:outline-none focus:ring-2 focus:ring-brand-500"
        />
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
      </div>

      <div className="bg-white rounded-xl border border-gray-200 shadow-sm overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-xs text-gray-500 bg-gray-50 border-b border-gray-100">
              {['CVE ID', 'Severity', 'CVSS v3', 'EPSS', 'Title', 'Published'].map((h) => (
                <th key={h} className="px-4 py-3 text-left font-medium">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-100">
            {isLoading && (
              <tr><td colSpan={6} className="px-4 py-8 text-center text-gray-400">Loading…</td></tr>
            )}
            {data?.map((v) => (
              <tr key={v.id} className="hover:bg-gray-50">
                <td className="px-4 py-3 font-mono text-blue-700 font-medium">{v.id}</td>
                <td className="px-4 py-3"><SeverityBadge severity={v.severity} /></td>
                <td className="px-4 py-3 tabular-nums">{v.cvss_v3_score?.toFixed(1) ?? '—'}</td>
                <td className="px-4 py-3 tabular-nums text-orange-700">
                  {v.epss_score != null ? (v.epss_score * 100).toFixed(2) + '%' : '—'}
                </td>
                <td className="px-4 py-3 text-gray-600 max-w-xs truncate">{v.title ?? '—'}</td>
                <td className="px-4 py-3 text-gray-500 text-xs">
                  {v.published_at ? new Date(v.published_at).toLocaleDateString() : '—'}
                </td>
              </tr>
            ))}
            {!isLoading && !data?.length && (
              <tr>
                <td colSpan={6} className="px-4 py-10 text-center text-gray-400">
                  No vulnerabilities cached yet. Run a scan to populate.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
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
          disabled={(data?.length ?? 0) < 50}
          onClick={() => setPage((p) => p + 1)}
          className="px-3 py-1.5 text-sm border border-gray-200 rounded-lg hover:bg-gray-50 disabled:opacity-40"
        >
          Next
        </button>
      </div>
    </div>
  )
}
