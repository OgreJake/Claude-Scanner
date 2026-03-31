import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { Plus, XCircle, Download, ChevronRight, ChevronDown } from 'lucide-react'
import { listScans, createScan, cancelScan, downloadScanPdf, getDeviceTree } from '../lib/api'
import type { ScanJob, DeviceTree } from '../types'
import { format } from 'date-fns'

const STATUS_COLOR: Record<string, string> = {
  completed: 'text-green-700 bg-green-50',
  running:   'text-yellow-700 bg-yellow-50',
  failed:    'text-red-700 bg-red-50',
  cancelled: 'text-gray-500 bg-gray-100',
  pending:   'text-blue-700 bg-blue-50',
}

// ---------------------------------------------------------------------------
// Device tree picker
// ---------------------------------------------------------------------------

function DeviceTreePicker({
  tree,
  selectedDeviceIds,
  selectedGroupIds,
  onToggleDevice,
  onToggleGroup,
}: {
  tree: DeviceTree
  selectedDeviceIds: Set<string>
  selectedGroupIds: Set<string>
  onToggleDevice: (id: string) => void
  onToggleGroup: (groupId: string, deviceIds: string[]) => void
}) {
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set())

  function toggleCollapse(id: string) {
    setCollapsed((prev) => {
      const next = new Set(prev)
      next.has(id) ? next.delete(id) : next.add(id)
      return next
    })
  }

  return (
    <div className="max-h-64 overflow-y-auto border border-gray-200 rounded-lg text-sm">
      {/* Groups */}
      {tree.groups.map((g) => {
        const isCollapsed = collapsed.has(g.id)
        const groupChecked = selectedGroupIds.has(g.id)
        const deviceIds = g.devices.map((d) => d.id)
        const someSelected = deviceIds.some((id) => selectedDeviceIds.has(id))
        const allSelected = deviceIds.length > 0 && deviceIds.every((id) => selectedDeviceIds.has(id))

        return (
          <div key={g.id}>
            <div className="flex items-center gap-2 px-3 py-2 bg-gray-50 border-b border-gray-100 hover:bg-gray-100 cursor-pointer">
              <button
                onClick={() => toggleCollapse(g.id)}
                className="text-gray-400 hover:text-gray-600 flex-shrink-0"
              >
                {isCollapsed ? <ChevronRight size={14} /> : <ChevronDown size={14} />}
              </button>
              <input
                type="checkbox"
                checked={groupChecked || allSelected}
                ref={(el) => {
                  if (el) el.indeterminate = !groupChecked && !allSelected && someSelected
                }}
                onChange={() => onToggleGroup(g.id, deviceIds)}
                className="rounded border-gray-300 text-brand-700"
                onClick={(e) => e.stopPropagation()}
              />
              <span
                className="w-2.5 h-2.5 rounded-full flex-shrink-0"
                style={{ backgroundColor: g.color ?? '#6b7280' }}
              />
              <span className="font-medium text-gray-800">{g.name}</span>
              <span className="text-xs text-gray-400 ml-auto">{g.devices.length} devices</span>
            </div>
            {!isCollapsed && g.devices.map((d) => (
              <label
                key={d.id}
                className="flex items-center gap-3 pl-10 pr-3 py-2 border-b border-gray-50 hover:bg-gray-50 cursor-pointer"
              >
                <input
                  type="checkbox"
                  checked={selectedDeviceIds.has(d.id) || selectedGroupIds.has(g.id)}
                  onChange={() => onToggleDevice(d.id)}
                  className="rounded border-gray-300 text-brand-700"
                />
                <span className="text-gray-700">{d.hostname}</span>
                <span className="text-xs text-gray-400 font-mono ml-auto">{d.ip_address}</span>
              </label>
            ))}
          </div>
        )
      })}

      {/* Ungrouped */}
      {tree.ungrouped.length > 0 && (
        <div>
          <div className="flex items-center gap-2 px-3 py-2 bg-gray-50 border-b border-gray-100">
            <span className="w-4 flex-shrink-0" />
            <span className="font-medium text-gray-500 text-xs uppercase tracking-wide">Ungrouped</span>
            <span className="text-xs text-gray-400 ml-auto">{tree.ungrouped.length} devices</span>
          </div>
          {tree.ungrouped.map((d) => (
            <label
              key={d.id}
              className="flex items-center gap-3 pl-7 pr-3 py-2 border-b border-gray-50 hover:bg-gray-50 cursor-pointer"
            >
              <input
                type="checkbox"
                checked={selectedDeviceIds.has(d.id)}
                onChange={() => onToggleDevice(d.id)}
                className="rounded border-gray-300 text-brand-700"
              />
              <span className="text-gray-700">{d.hostname}</span>
              <span className="text-xs text-gray-400 font-mono ml-auto">{d.ip_address}</span>
            </label>
          ))}
        </div>
      )}

      {tree.groups.length === 0 && tree.ungrouped.length === 0 && (
        <p className="px-3 py-4 text-xs text-gray-400 text-center">
          No devices found. Add one on the Devices page first.
        </p>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

export default function Scans() {
  const qc = useQueryClient()
  const [showNew, setShowNew] = useState(false)
  const [scanName, setScanName] = useState('')
  const [scanType, setScanType] = useState('full')
  const [selectedDeviceIds, setSelectedDeviceIds] = useState<Set<string>>(new Set())
  const [selectedGroupIds, setSelectedGroupIds] = useState<Set<string>>(new Set())

  const { data: scans, isLoading } = useQuery<ScanJob[]>({
    queryKey: ['scans'],
    queryFn: () => listScans({ page_size: 50 }).then((r) => r.data),
    refetchInterval: 5000,
  })

  const { data: tree, isLoading: treeLoading } = useQuery<DeviceTree>({
    queryKey: ['deviceTree'],
    queryFn: () => getDeviceTree().then((r) => r.data),
    enabled: showNew,
  })

  const totalSelected =
    selectedDeviceIds.size +
    (tree?.groups ?? [])
      .filter((g) => selectedGroupIds.has(g.id))
      .reduce((sum, g) => {
        // avoid double-counting devices already in selectedDeviceIds
        const extra = g.devices.filter((d) => !selectedDeviceIds.has(d.id)).length
        return sum + extra
      }, 0)

  const createMutation = useMutation({
    mutationFn: () =>
      createScan({
        name: scanName,
        scan_type: scanType,
        device_ids: Array.from(selectedDeviceIds),
        group_ids: Array.from(selectedGroupIds),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['scans'] })
      setShowNew(false)
      setScanName('')
      setSelectedDeviceIds(new Set())
      setSelectedGroupIds(new Set())
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

  function toggleDevice(id: string) {
    setSelectedDeviceIds((prev) => {
      const next = new Set(prev)
      next.has(id) ? next.delete(id) : next.add(id)
      return next
    })
  }

  function toggleGroup(groupId: string, deviceIds: string[]) {
    const isSelected = selectedGroupIds.has(groupId)
    setSelectedGroupIds((prev) => {
      const next = new Set(prev)
      isSelected ? next.delete(groupId) : next.add(groupId)
      return next
    })
    // Also update individual device selections to stay consistent
    setSelectedDeviceIds((prev) => {
      const next = new Set(prev)
      if (isSelected) {
        deviceIds.forEach((id) => next.delete(id))
      } else {
        deviceIds.forEach((id) => next.add(id))
      }
      return next
    })
  }

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
              Select Devices
              {totalSelected > 0 && (
                <span className="ml-2 text-brand-700 font-semibold">{totalSelected} selected</span>
              )}
            </label>
            {treeLoading ? (
              <div className="border border-gray-200 rounded-lg px-3 py-4 text-xs text-gray-400 text-center">
                Loading devices…
              </div>
            ) : tree ? (
              <DeviceTreePicker
                tree={tree}
                selectedDeviceIds={selectedDeviceIds}
                selectedGroupIds={selectedGroupIds}
                onToggleDevice={toggleDevice}
                onToggleGroup={toggleGroup}
              />
            ) : null}
          </div>

          <div className="flex gap-2">
            <button
              onClick={() => createMutation.mutate()}
              disabled={!scanName || totalSelected === 0 || createMutation.isPending}
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
