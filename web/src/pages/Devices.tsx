import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus, Search, Trash2, RefreshCw } from 'lucide-react'
import { listDevices, createDevice, deleteDevice } from '../lib/api'
import type { DeviceListResponse } from '../types'
import { format } from 'date-fns'

const OS_ICONS: Record<string, string> = {
  linux: '🐧', windows: '🪟', darwin: '🍎', unix: '⚙️', unknown: '❓',
}

const STATUS_DOT: Record<string, string> = {
  online: 'bg-green-500', offline: 'bg-red-500', unknown: 'bg-gray-400',
}

export default function Devices() {
  const qc = useQueryClient()
  const [search, setSearch] = useState('')
  const [showAdd, setShowAdd] = useState(false)
  const [form, setForm] = useState({
    hostname: '', ip_address: '', os_type: 'unknown',
    credential_ref: '', notes: '',
  })

  const { data, isLoading, refetch } = useQuery<DeviceListResponse>({
    queryKey: ['devices', search],
    queryFn: () => listDevices({ search: search || undefined, page_size: 200 }).then((r) => r.data),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => deleteDevice(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['devices'] }),
  })

  const addMutation = useMutation({
    mutationFn: () =>
      createDevice({
        ...form,
        credential_ref: form.credential_ref || undefined,
        notes: form.notes || undefined,
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['devices'] })
      setShowAdd(false)
      setForm({ hostname: '', ip_address: '', os_type: 'unknown', credential_ref: '', notes: '' })
    },
  })

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Devices</h1>
          <p className="text-sm text-gray-500 mt-0.5">{data?.total ?? 0} registered devices</p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => refetch()}
            className="p-2 rounded-lg border border-gray-200 hover:bg-gray-50 text-gray-600"
          >
            <RefreshCw size={16} />
          </button>
          <button
            onClick={() => setShowAdd(true)}
            className="flex items-center gap-2 bg-brand-700 text-white px-4 py-2 rounded-lg text-sm
                       font-medium hover:bg-brand-800 transition-colors"
          >
            <Plus size={16} /> Add Device
          </button>
        </div>
      </div>

      {/* Search */}
      <div className="relative">
        <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" />
        <input
          type="text"
          placeholder="Search hostname or IP…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="pl-9 pr-4 py-2 w-full max-w-sm border border-gray-200 rounded-lg text-sm
                     focus:outline-none focus:ring-2 focus:ring-brand-500"
        />
      </div>

      {/* Add device form */}
      {showAdd && (
        <div className="bg-white border border-gray-200 rounded-xl p-5 shadow-sm">
          <h3 className="text-sm font-semibold mb-4">Add New Device</h3>
          <div className="grid grid-cols-2 gap-4">
            {[
              ['hostname', 'Hostname', 'text'],
              ['ip_address', 'IP Address', 'text'],
              ['credential_ref', '1Password Ref (optional)', 'text'],
              ['notes', 'Notes (optional)', 'text'],
            ].map(([field, label]) => (
              <div key={field}>
                <label className="block text-xs font-medium text-gray-700 mb-1">{label}</label>
                <input
                  value={form[field as keyof typeof form]}
                  onChange={(e) => setForm((f) => ({ ...f, [field]: e.target.value }))}
                  className="w-full border border-gray-200 rounded-lg px-3 py-1.5 text-sm
                             focus:outline-none focus:ring-2 focus:ring-brand-500"
                />
              </div>
            ))}
            <div>
              <label className="block text-xs font-medium text-gray-700 mb-1">OS Type</label>
              <select
                value={form.os_type}
                onChange={(e) => setForm((f) => ({ ...f, os_type: e.target.value }))}
                className="w-full border border-gray-200 rounded-lg px-3 py-1.5 text-sm
                           focus:outline-none focus:ring-2 focus:ring-brand-500"
              >
                {['linux', 'windows', 'darwin', 'unix', 'unknown'].map((o) => (
                  <option key={o} value={o}>{o}</option>
                ))}
              </select>
            </div>
          </div>
          <div className="flex gap-2 mt-4">
            <button
              onClick={() => addMutation.mutate()}
              disabled={!form.hostname || !form.ip_address || addMutation.isPending}
              className="bg-brand-700 text-white px-4 py-1.5 rounded-lg text-sm font-medium
                         hover:bg-brand-800 disabled:opacity-50"
            >
              {addMutation.isPending ? 'Adding…' : 'Add Device'}
            </button>
            <button
              onClick={() => setShowAdd(false)}
              className="px-4 py-1.5 rounded-lg text-sm border border-gray-200 hover:bg-gray-50"
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      {/* Device table */}
      <div className="bg-white rounded-xl border border-gray-200 shadow-sm overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-xs text-gray-500 bg-gray-50 border-b border-gray-100">
              {['Status', 'Hostname', 'IP Address', 'OS', 'Version', 'Agent', 'Last Scanned', ''].map((h) => (
                <th key={h} className="px-4 py-3 text-left font-medium">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-100">
            {isLoading && (
              <tr><td colSpan={8} className="px-4 py-8 text-center text-gray-400">Loading…</td></tr>
            )}
            {data?.items.map((d) => (
              <tr key={d.id} className="hover:bg-gray-50 transition-colors">
                <td className="px-4 py-3">
                  <span className={`inline-block w-2 h-2 rounded-full ${STATUS_DOT[d.status]}`} />
                </td>
                <td className="px-4 py-3 font-medium text-gray-900">{d.hostname}</td>
                <td className="px-4 py-3 font-mono text-gray-600">{d.ip_address}</td>
                <td className="px-4 py-3">
                  {OS_ICONS[d.os_type]} {d.os_type}
                </td>
                <td className="px-4 py-3 text-gray-500">{d.os_version ?? '—'}</td>
                <td className="px-4 py-3">
                  {d.agent_installed ? (
                    <span className="text-green-700 bg-green-50 text-xs px-2 py-0.5 rounded-full">Installed</span>
                  ) : (
                    <span className="text-gray-400 text-xs">Agentless</span>
                  )}
                </td>
                <td className="px-4 py-3 text-gray-500">
                  {d.last_scanned_at ? format(new Date(d.last_scanned_at), 'MMM d HH:mm') : 'Never'}
                </td>
                <td className="px-4 py-3">
                  <button
                    onClick={() => {
                      if (confirm(`Delete device ${d.hostname}?`)) {
                        deleteMutation.mutate(d.id)
                      }
                    }}
                    className="text-gray-400 hover:text-red-600 transition-colors p-1 rounded"
                  >
                    <Trash2 size={14} />
                  </button>
                </td>
              </tr>
            ))}
            {!isLoading && !data?.items.length && (
              <tr>
                <td colSpan={8} className="px-4 py-10 text-center text-gray-400">
                  No devices found. Add one above or run discovery.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
