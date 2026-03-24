import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { Plus, XCircle, Download } from 'lucide-react'
import { listScans, createScan, cancelScan, listDevices, downloadScanPdf } from '../lib/api'
import type { ScanJob, DeviceListResponse } from '../types'
import { format } from 'date-fns'

const STATUS_COLOR: Record<string, string> = {
  completed: 'text-green-700 bg-green-50',
  running:   'text-yellow-700 bg-yellow-50',
  failed:    'text-red-700 bg-red-50',
  cancelled: 'text-gray-500 bg-gray-100',
  pending:   'text-blue-700 bg-blue-50',
}

export default function Scans() {
  const qc = useQueryClient()
  const [showNew, setShowNew] = useState(false)
  const [scanName, setScanName] = useState('')
  const [scanType, setScanType] = useState('full')
  const [selectedDevices, setSelectedDevices] = useState<string[]>([])

  const { data: scans, isLoading } = useQuery<ScanJob[]>({
    queryKey: ['scans'],
    queryFn: () => listScans({ page_size: 50 }).then((r) => r.data),
    refetchInterval: 5000, // poll every 5s while scans are running
  })

  const { data: devicesData } = useQuery<DeviceListResponse>({
    queryKey: ['devices-all'],
    queryFn: () => listDevices({ page_size: 1000 }).then((r) => r.data),
    enabled: showNew,
  })

  const createMutation = useMutation({
    mutationFn: () =>
      createScan({ name: scanName, scan_type: scanType, device_ids: selectedDevices }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['scans'] })
      setShowNew(false)
      setScanName('')
      setSelectedDevices([])
    },
  })

  const cancelMutation = useMutation({
    mutationFn: (id: string) => cancelScan(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['scans'] }),
  })

  async function handleDownloadPdf(scanId: string, scanName: string) {
    const res = await downloadScanPdf(scanId)
    const url = URL.createObjectURL(new Blob([res.data], { type: 'application/pdf' }))
    const a = document.createElement('a')
    a.href = url
    a.download = `scan-report-${scanName.replace(/\s+/g, '-')}.pdf`
    a.click()
  }

  const toggleDevice = (id: string) =>
    setSelectedDevices((prev) =>
      prev.includes(id) ? prev.filter((d) => d !== id) : [...prev, id],
    )

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Scans</h1>
          <p className="text-sm text-gray-500 mt-0.5">Manage and monitor scan jobs</p>
        </div>
        <button
          onClick={() => setShowNew(true)}
          className="flex items-center gap-2 bg-brand-700 text-white px-4 py-2 rounded-lg text-sm
                     font-medium hover:bg-brand-800 transition-colors"
        >
          <Plus size={16} /> New Scan
        </button>
      </div>

      {/* New scan form */}
      {showNew && (
        <div className="bg-white border border-gray-200 rounded-xl p-5 shadow-sm space-y-4">
          <h3 className="text-sm font-semibold">Create New Scan</h3>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-medium text-gray-700 mb-1">Scan Name</label>
              <input
                value={scanName}
                onChange={(e) => setScanName(e.target.value)}
                placeholder="Production Scan — Q3"
                className="w-full border border-gray-200 rounded-lg px-3 py-1.5 text-sm
                           focus:outline-none focus:ring-2 focus:ring-brand-500"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-700 mb-1">Scan Type</label>
              <select
                value={scanType}
                onChange={(e) => setScanType(e.target.value)}
                className="w-full border border-gray-200 rounded-lg px-3 py-1.5 text-sm
                           focus:outline-none focus:ring-2 focus:ring-brand-500"
              >
                {['full', 'packages', 'network', 'config', 'quick'].map((t) => (
                  <option key={t} value={t}>{t}</option>
                ))}
              </select>
            </div>
          </div>

          <div>
            <label className="block text-xs font-medium text-gray-700 mb-2">
              Select Devices ({selectedDevices.length} selected)
            </label>
            <div className="max-h-48 overflow-y-auto border border-gray-200 rounded-lg divide-y">
              {devicesData?.items.map((d) => (
                <label key={d.id} className="flex items-center gap-3 px-3 py-2 hover:bg-gray-50 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={selectedDevices.includes(d.id)}
                    onChange={() => toggleDevice(d.id)}
                    className="rounded border-gray-300 text-brand-700"
                  />
                  <span className="text-sm text-gray-700">{d.hostname}</span>
                  <span className="text-xs text-gray-400 font-mono">{d.ip_address}</span>
                </label>
              ))}
            </div>
          </div>

          <div className="flex gap-2">
            <button
              onClick={() => createMutation.mutate()}
              disabled={!scanName || selectedDevices.length === 0 || createMutation.isPending}
              className="bg-brand-700 text-white px-4 py-1.5 rounded-lg text-sm font-medium
                         hover:bg-brand-800 disabled:opacity-50"
            >
              {createMutation.isPending ? 'Starting…' : 'Start Scan'}
            </button>
            <button
              onClick={() => setShowNew(false)}
              className="px-4 py-1.5 rounded-lg text-sm border border-gray-200 hover:bg-gray-50"
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      {/* Scans table */}
      <div className="bg-white rounded-xl border border-gray-200 shadow-sm overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-xs text-gray-500 bg-gray-50 border-b border-gray-100">
              {['Name', 'Type', 'Status', 'Progress', 'Created', 'Completed', ''].map((h) => (
                <th key={h} className="px-4 py-3 text-left font-medium">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-100">
            {isLoading && (
              <tr><td colSpan={7} className="px-4 py-8 text-center text-gray-400">Loading…</td></tr>
            )}
            {scans?.map((scan) => {
              const pct = scan.total_devices > 0
                ? Math.round((scan.completed_devices / scan.total_devices) * 100) : 0
              return (
                <tr key={scan.id} className="hover:bg-gray-50 transition-colors">
                  <td className="px-4 py-3">
                    <Link to={`/scans/${scan.id}`} className="font-medium text-brand-700 hover:underline">
                      {scan.name}
                    </Link>
                  </td>
                  <td className="px-4 py-3 text-gray-500 capitalize">{scan.scan_type}</td>
                  <td className="px-4 py-3">
                    <span className={`text-xs font-medium px-2 py-0.5 rounded-full ${STATUS_COLOR[scan.status]}`}>
                      {scan.status}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <div className="w-20 bg-gray-200 rounded-full h-1.5">
                        <div
                          className="bg-brand-600 h-1.5 rounded-full transition-all"
                          style={{ width: `${pct}%` }}
                        />
                      </div>
                      <span className="text-xs text-gray-500">
                        {scan.completed_devices}/{scan.total_devices}
                      </span>
                    </div>
                  </td>
                  <td className="px-4 py-3 text-gray-500">
                    {format(new Date(scan.created_at), 'MMM d, HH:mm')}
                  </td>
                  <td className="px-4 py-3 text-gray-500">
                    {scan.completed_at ? format(new Date(scan.completed_at), 'MMM d, HH:mm') : '—'}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-1">
                      {scan.status === 'completed' && (
                        <button
                          onClick={() => handleDownloadPdf(scan.id, scan.name)}
                          className="p-1.5 rounded text-gray-400 hover:text-brand-700 hover:bg-gray-100"
                          title="Download PDF"
                        >
                          <Download size={14} />
                        </button>
                      )}
                      {['pending', 'running'].includes(scan.status) && (
                        <button
                          onClick={() => cancelMutation.mutate(scan.id)}
                          className="p-1.5 rounded text-gray-400 hover:text-red-600 hover:bg-gray-100"
                          title="Cancel scan"
                        >
                          <XCircle size={14} />
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              )
            })}
            {!isLoading && !scans?.length && (
              <tr>
                <td colSpan={7} className="px-4 py-10 text-center text-gray-400">
                  No scans yet. Click "New Scan" to get started.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
