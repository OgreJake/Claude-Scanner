import { useParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { getScan } from '../lib/api'
import type { ScanJob } from '../types'
import { format } from 'date-fns'

const STATUS_COLOR: Record<string, string> = {
  completed: 'text-green-700 bg-green-50',
  running:   'text-yellow-700 bg-yellow-50',
  failed:    'text-red-700 bg-red-50',
  cancelled: 'text-gray-500 bg-gray-100',
  pending:   'text-blue-700 bg-blue-50',
}

export default function ScanDetail() {
  const { id } = useParams<{ id: string }>()
  const { data: scan, isLoading } = useQuery<ScanJob>({
    queryKey: ['scan', id],
    queryFn: () => getScan(id!).then((r) => r.data),
    refetchInterval: (query) =>
      query.state.data?.status === 'running' || query.state.data?.status === 'pending' ? 3000 : false,
  })

  if (isLoading) return <div className="text-gray-400 p-8">Loading…</div>
  if (!scan) return <div className="text-red-600 p-8">Scan not found</div>

  const pct = scan.total_devices > 0
    ? Math.round((scan.completed_devices / scan.total_devices) * 100) : 0

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">{scan.name}</h1>
        <p className="text-sm text-gray-500 mt-0.5">
          {scan.scan_type} scan · {format(new Date(scan.created_at), 'PPpp')}
        </p>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {[
          { label: 'Status', value: <span className={`text-xs font-medium px-2 py-0.5 rounded-full ${STATUS_COLOR[scan.status]}`}>{scan.status}</span> },
          { label: 'Total Devices', value: scan.total_devices },
          { label: 'Completed', value: scan.completed_devices },
          { label: 'Failed', value: scan.failed_devices },
        ].map(({ label, value }) => (
          <div key={label} className="bg-white rounded-xl border border-gray-200 p-4 shadow-sm">
            <p className="text-xs text-gray-500">{label}</p>
            <div className="text-xl font-bold text-gray-900 mt-1">{value}</div>
          </div>
        ))}
      </div>

      {/* Progress bar */}
      <div className="bg-white rounded-xl border border-gray-200 p-4 shadow-sm">
        <div className="flex justify-between text-sm text-gray-500 mb-2">
          <span>Overall Progress</span>
          <span>{pct}%</span>
        </div>
        <div className="w-full bg-gray-200 rounded-full h-3">
          <div
            className="bg-brand-600 h-3 rounded-full transition-all duration-500"
            style={{ width: `${pct}%` }}
          />
        </div>
      </div>

      {/* Targets table */}
      <div className="bg-white rounded-xl border border-gray-200 shadow-sm overflow-x-auto">
        <div className="px-5 py-4 border-b border-gray-100">
          <h2 className="text-sm font-semibold text-gray-700">Scan Targets</h2>
        </div>
        <table className="w-full text-sm">
          <thead>
            <tr className="text-xs text-gray-500 bg-gray-50 border-b border-gray-100">
              <th className="px-4 py-3 text-left font-medium">Device ID</th>
              <th className="px-4 py-3 text-left font-medium">Status</th>
              <th className="px-4 py-3 text-left font-medium">Started</th>
              <th className="px-4 py-3 text-left font-medium">Completed</th>
              <th className="px-4 py-3 text-left font-medium">Error</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-100">
            {scan.targets?.map((t) => (
              <tr key={t.id} className="hover:bg-gray-50">
                <td className="px-4 py-3 font-mono text-xs text-gray-600">{t.device_id.slice(0, 12)}…</td>
                <td className="px-4 py-3">
                  <span className={`text-xs font-medium px-2 py-0.5 rounded-full ${STATUS_COLOR[t.status]}`}>
                    {t.status}
                  </span>
                </td>
                <td className="px-4 py-3 text-gray-500 text-xs">
                  {t.started_at ? format(new Date(t.started_at), 'HH:mm:ss') : '—'}
                </td>
                <td className="px-4 py-3 text-gray-500 text-xs">
                  {t.completed_at ? format(new Date(t.completed_at), 'HH:mm:ss') : '—'}
                </td>
                <td className="px-4 py-3 text-red-500 text-xs">{t.error_message ?? ''}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
