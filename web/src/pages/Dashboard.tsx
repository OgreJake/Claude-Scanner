import { useQuery } from '@tanstack/react-query'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, Legend,
} from 'recharts'
import { ShieldAlert, Monitor, ScanSearch, AlertTriangle } from 'lucide-react'
import { getFindingsSummary, listScans, listDevices, getTopEpssFindings } from '../lib/api'
import type { FindingSummary, ScanJob, Device, Finding } from '../types'
import SeverityBadge from '../components/SeverityBadge'
import { format } from 'date-fns'

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#dc2626',
  high:     '#ea580c',
  medium:   '#d97706',
  low:      '#65a30d',
}

function StatCard({
  icon: Icon, label, value, sub, color = 'blue',
}: {
  icon: React.ElementType
  label: string
  value: number | string
  sub?: string
  color?: string
}) {
  const colorMap: Record<string, string> = {
    blue: 'bg-blue-50 text-blue-700',
    red: 'bg-red-50 text-red-700',
    orange: 'bg-orange-50 text-orange-700',
    green: 'bg-green-50 text-green-700',
  }
  return (
    <div className="bg-white rounded-xl border border-gray-200 p-5 flex items-start gap-4 shadow-sm">
      <div className={`p-2.5 rounded-lg ${colorMap[color]}`}>
        <Icon size={20} />
      </div>
      <div>
        <p className="text-sm text-gray-500">{label}</p>
        <p className="text-2xl font-bold text-gray-900 mt-0.5">{value}</p>
        {sub && <p className="text-xs text-gray-400 mt-0.5">{sub}</p>}
      </div>
    </div>
  )
}

export default function Dashboard() {
  const { data: summary } = useQuery<FindingSummary>({
    queryKey: ['findings-summary'],
    queryFn: () => getFindingsSummary().then((r) => r.data),
  })

  const { data: scansData } = useQuery<ScanJob[]>({
    queryKey: ['scans', { page_size: 5 }],
    queryFn: () => listScans({ page_size: 5 }).then((r) => r.data),
  })

  const { data: devicesData } = useQuery<{ total: number }>({
    queryKey: ['devices', { page_size: 1 }],
    queryFn: () => listDevices({ page_size: 1 }).then((r) => r.data),
  })

  const { data: topFindings } = useQuery<Finding[]>({
    queryKey: ['top-epss'],
    queryFn: () => getTopEpssFindings(10).then((r) => r.data),
  })

  const severityChartData = summary
    ? ['critical', 'high', 'medium', 'low'].map((s) => ({
        name: s.charAt(0).toUpperCase() + s.slice(1),
        count: summary[s as keyof FindingSummary] as number,
        fill: SEVERITY_COLORS[s],
      }))
    : []

  const statusPieData = summary
    ? [
        { name: 'Open', value: summary.open, fill: '#3b82f6' },
        { name: 'Acknowledged', value: summary.acknowledged, fill: '#d97706' },
        { name: 'Resolved', value: summary.resolved, fill: '#22c55e' },
        { name: 'False Positive', value: summary.false_positive, fill: '#9ca3af' },
      ].filter((d) => d.value > 0)
    : []

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Dashboard</h1>
        <p className="text-sm text-gray-500 mt-0.5">Fleet vulnerability overview</p>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          icon={Monitor}
          label="Total Devices"
          value={devicesData?.total ?? '—'}
          color="blue"
        />
        <StatCard
          icon={ShieldAlert}
          label="Total Findings"
          value={summary?.total ?? '—'}
          sub={`${summary?.open ?? 0} open`}
          color="orange"
        />
        <StatCard
          icon={AlertTriangle}
          label="Critical"
          value={summary?.critical ?? '—'}
          color="red"
        />
        <StatCard
          icon={ScanSearch}
          label="Recent Scans"
          value={scansData?.length ?? '—'}
          color="green"
        />
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Severity breakdown bar chart */}
        <div className="bg-white rounded-xl border border-gray-200 p-5 shadow-sm">
          <h2 className="text-sm font-semibold text-gray-700 mb-4">Findings by Severity</h2>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={severityChartData} barSize={32}>
              <XAxis dataKey="name" tick={{ fontSize: 12 }} />
              <YAxis tick={{ fontSize: 12 }} />
              <Tooltip />
              <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                {severityChartData.map((entry, index) => (
                  <Cell key={index} fill={entry.fill} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Status pie chart */}
        <div className="bg-white rounded-xl border border-gray-200 p-5 shadow-sm">
          <h2 className="text-sm font-semibold text-gray-700 mb-4">Finding Status</h2>
          <ResponsiveContainer width="100%" height={200}>
            <PieChart>
              <Pie data={statusPieData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={70}>
                {statusPieData.map((entry, index) => (
                  <Cell key={index} fill={entry.fill} />
                ))}
              </Pie>
              <Legend />
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Top findings by EPSS */}
      <div className="bg-white rounded-xl border border-gray-200 shadow-sm">
        <div className="px-5 py-4 border-b border-gray-100">
          <h2 className="text-sm font-semibold text-gray-700">Top Findings by EPSS Score</h2>
          <p className="text-xs text-gray-400 mt-0.5">Ranked by exploitation probability</p>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-xs text-gray-500 bg-gray-50">
                <th className="px-5 py-3 text-left font-medium">CVE ID</th>
                <th className="px-5 py-3 text-left font-medium">Component</th>
                <th className="px-5 py-3 text-left font-medium">Severity</th>
                <th className="px-5 py-3 text-right font-medium">CVSS</th>
                <th className="px-5 py-3 text-right font-medium">EPSS</th>
                <th className="px-5 py-3 text-right font-medium">Percentile</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {topFindings?.map((f) => (
                <tr key={f.id} className="hover:bg-gray-50 transition-colors">
                  <td className="px-5 py-3 font-mono text-blue-700">{f.vulnerability_id}</td>
                  <td className="px-5 py-3 text-gray-700">{f.affected_component ?? '—'}</td>
                  <td className="px-5 py-3">
                    <SeverityBadge severity={f.severity} />
                  </td>
                  <td className="px-5 py-3 text-right tabular-nums">
                    {f.cvss_score?.toFixed(1) ?? '—'}
                  </td>
                  <td className="px-5 py-3 text-right tabular-nums font-medium text-orange-700">
                    {f.epss_score != null ? (f.epss_score * 100).toFixed(2) + '%' : '—'}
                  </td>
                  <td className="px-5 py-3 text-right tabular-nums">
                    {f.epss_percentile != null ? (f.epss_percentile * 100).toFixed(0) + 'th' : '—'}
                  </td>
                </tr>
              ))}
              {!topFindings?.length && (
                <tr>
                  <td colSpan={6} className="px-5 py-8 text-center text-gray-400 text-sm">
                    No findings yet. Run a scan to populate this table.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Recent scans */}
      <div className="bg-white rounded-xl border border-gray-200 shadow-sm">
        <div className="px-5 py-4 border-b border-gray-100 flex items-center justify-between">
          <h2 className="text-sm font-semibold text-gray-700">Recent Scans</h2>
        </div>
        <div className="divide-y divide-gray-100">
          {scansData?.map((scan) => {
            const pct = scan.total_devices > 0
              ? Math.round((scan.completed_devices / scan.total_devices) * 100)
              : 0
            const statusColor: Record<string, string> = {
              completed: 'text-green-700 bg-green-50',
              running: 'text-yellow-700 bg-yellow-50',
              failed: 'text-red-700 bg-red-50',
              cancelled: 'text-gray-500 bg-gray-100',
              pending: 'text-blue-700 bg-blue-50',
            }
            return (
              <div key={scan.id} className="px-5 py-3 flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-gray-900">{scan.name}</p>
                  <p className="text-xs text-gray-400">
                    {format(new Date(scan.created_at), 'MMM d, yyyy HH:mm')} · {scan.scan_type}
                  </p>
                </div>
                <div className="flex items-center gap-4">
                  <div className="text-xs text-gray-500 text-right">
                    {scan.completed_devices}/{scan.total_devices} devices
                  </div>
                  <span className={`text-xs font-medium px-2 py-0.5 rounded-full ${statusColor[scan.status] ?? ''}`}>
                    {scan.status}
                  </span>
                </div>
              </div>
            )
          })}
          {!scansData?.length && (
            <p className="px-5 py-8 text-center text-gray-400 text-sm">No scans yet.</p>
          )}
        </div>
      </div>
    </div>
  )
}
