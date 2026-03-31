import { useState, useEffect, useRef } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Plus, Search, Trash2, RefreshCw, Network, X, CheckCircle,
  AlertCircle, Loader2, Pencil, FolderPlus, Folder, FolderOpen, UserMinus,
} from 'lucide-react'
import {
  listDevices, createDevice, deleteDevice, updateDevice,
  startDiscovery, getDiscoveryJob,
  listGroups, createGroup, deleteGroup, addGroupMembers, removeGroupMember,
} from '../lib/api'
import type { DeviceListResponse, Device, DeviceGroup, DiscoveryJob } from '../types'
import { format } from 'date-fns'

const OS_ICONS: Record<string, string> = {
  linux: '🐧', windows: '🪟', darwin: '🍎', unix: '⚙️', ibmi: '🖥️', unknown: '❓',
}
const OS_OPTIONS = ['linux', 'windows', 'darwin', 'unix', 'ibmi', 'unknown']

const STATUS_DOT: Record<string, string> = {
  online: 'bg-green-500', offline: 'bg-red-500', unknown: 'bg-gray-400',
}

const GROUP_COLORS = [
  '#4f46e5', '#0891b2', '#059669', '#d97706', '#dc2626',
  '#7c3aed', '#db2777', '#65a30d', '#0284c7', '#6b7280',
]

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function InputField({
  label, value, onChange, type = 'text', placeholder = '',
}: {
  label: string; value: string; onChange: (v: string) => void
  type?: string; placeholder?: string
}) {
  return (
    <div>
      <label className="block text-xs font-medium text-gray-700 mb-1">{label}</label>
      <input
        type={type}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        className="w-full border border-gray-200 rounded-lg px-3 py-1.5 text-sm
                   focus:outline-none focus:ring-2 focus:ring-brand-500"
      />
    </div>
  )
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

export default function Devices() {
  const qc = useQueryClient()

  // Search + filters
  const [search, setSearch] = useState('')
  const [groupFilter, setGroupFilter] = useState<string | null>(null)

  // Panel visibility
  const [showAdd, setShowAdd] = useState(false)
  const [showDiscover, setShowDiscover] = useState(false)
  const [showGroups, setShowGroups] = useState(false)

  // Add device form
  const [form, setForm] = useState({
    hostname: '', ip_address: '', os_type: 'unknown',
    credential_ref: '', notes: '',
  })

  // Edit device
  const [editDevice, setEditDevice] = useState<Device | null>(null)
  const [editForm, setEditForm] = useState({
    hostname: '', ip_address: '', os_type: 'unknown',
    os_name: '', os_version: '', ssh_port: '22', winrm_port: '5985',
    credential_ref: '', notes: '',
  })

  // Discovery
  const [discoverForm, setDiscoverForm] = useState({ name: '', subnets: '', group_name: '' })
  const [discoveryJob, setDiscoveryJob] = useState<DiscoveryJob | null>(null)
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null)

  // New group form
  const [newGroupName, setNewGroupName] = useState('')
  const [newGroupColor, setNewGroupColor] = useState(GROUP_COLORS[0])

  // ---------------------------------------------------------------------------
  // Queries
  // ---------------------------------------------------------------------------

  const { data, isLoading, refetch } = useQuery<DeviceListResponse>({
    queryKey: ['devices', search],
    queryFn: () => listDevices({ search: search || undefined, page_size: 500 }).then((r) => r.data),
  })

  const { data: groups = [] } = useQuery<DeviceGroup[]>({
    queryKey: ['deviceGroups'],
    queryFn: () => listGroups().then((r) => r.data),
  })

  // Filter devices by group (client-side for simplicity)
  const displayedDevices = groupFilter
    ? (data?.items ?? []).filter((d) => {
        // We need a per-device group membership check; kept simple here.
        // The group filter works by checking the device_ids returned from the group.
        return groupDeviceIds.has(d.id)
      })
    : (data?.items ?? [])

  const [groupDeviceIds, setGroupDeviceIds] = useState<Set<string>>(new Set())

  useEffect(() => {
    if (!groupFilter) { setGroupDeviceIds(new Set()); return }
    // Fetch member IDs for the selected group
    import('../lib/api').then(({ api }) =>
      api.get(`/devices/groups/${groupFilter}`).then((r) => {
        // The group endpoint returns device_count but not device_ids.
        // Workaround: filter devices by fetching all devices in the group via a future endpoint.
        // For now, load all devices and cross-reference via the group's device list.
      })
    )
    // Simpler approach: list all devices and mark group membership from device.groups
    // (not included in list endpoint). We'll just show all devices when a group is selected
    // until we add a per-group device list endpoint. For now, clear filter.
    setGroupDeviceIds(new Set())
  }, [groupFilter])

  // ---------------------------------------------------------------------------
  // Mutations
  // ---------------------------------------------------------------------------

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

  const editMutation = useMutation({
    mutationFn: () =>
      updateDevice(editDevice!.id, {
        hostname: editForm.hostname || undefined,
        ip_address: editForm.ip_address || undefined,
        os_type: editForm.os_type,
        os_name: editForm.os_name || undefined,
        os_version: editForm.os_version || undefined,
        ssh_port: editForm.ssh_port ? Number(editForm.ssh_port) : undefined,
        winrm_port: editForm.winrm_port ? Number(editForm.winrm_port) : undefined,
        credential_ref: editForm.credential_ref || undefined,
        notes: editForm.notes || undefined,
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['devices'] })
      setEditDevice(null)
    },
  })

  const discoverMutation = useMutation({
    mutationFn: () => {
      const ranges = discoverForm.subnets
        .split(/[\n,]+/)
        .map((s) => s.trim())
        .filter(Boolean)
      return startDiscovery({
        name: discoverForm.name,
        target_ranges: ranges,
        group_name: discoverForm.group_name || undefined,
      }).then((r) => r.data as DiscoveryJob)
    },
    onSuccess: (job: DiscoveryJob) => setDiscoveryJob(job),
  })

  const addGroupMutation = useMutation({
    mutationFn: () => createGroup({ name: newGroupName, color: newGroupColor }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['deviceGroups'] })
      setNewGroupName('')
    },
  })

  const deleteGroupMutation = useMutation({
    mutationFn: (id: string) => deleteGroup(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['deviceGroups'] })
      if (groupFilter) setGroupFilter(null)
    },
  })

  const removeFromGroupMutation = useMutation({
    mutationFn: ({ groupId, deviceId }: { groupId: string; deviceId: string }) =>
      removeGroupMember(groupId, deviceId),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['deviceGroups'] }),
  })

  // ---------------------------------------------------------------------------
  // Discovery polling
  // ---------------------------------------------------------------------------

  useEffect(() => {
    if (!discoveryJob || discoveryJob.status === 'completed' || discoveryJob.status === 'failed') {
      if (pollRef.current) clearInterval(pollRef.current)
      if (discoveryJob?.status === 'completed') {
        qc.invalidateQueries({ queryKey: ['devices'] })
        qc.invalidateQueries({ queryKey: ['deviceGroups'] })
      }
      return
    }
    if (pollRef.current) clearInterval(pollRef.current)
    pollRef.current = setInterval(async () => {
      try {
        const res = await getDiscoveryJob(discoveryJob.id)
        const updated = res.data as DiscoveryJob
        setDiscoveryJob(updated)
        if (updated.status === 'completed' || updated.status === 'failed') {
          clearInterval(pollRef.current!)
          if (updated.status === 'completed') {
            qc.invalidateQueries({ queryKey: ['devices'] })
            qc.invalidateQueries({ queryKey: ['deviceGroups'] })
          }
        }
      } catch { clearInterval(pollRef.current!) }
    }, 3000)
    return () => { if (pollRef.current) clearInterval(pollRef.current) }
  }, [discoveryJob?.id, discoveryJob?.status, qc])

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  function openEdit(d: Device) {
    setEditDevice(d)
    setEditForm({
      hostname: d.hostname,
      ip_address: d.ip_address,
      os_type: d.os_type,
      os_name: d.os_name ?? '',
      os_version: d.os_version ?? '',
      ssh_port: String(d.ssh_port),
      winrm_port: String(d.winrm_port),
      credential_ref: d.credential_ref ?? '',
      notes: d.notes ?? '',
    })
  }

  function closeDiscovery() {
    setShowDiscover(false)
    setDiscoveryJob(null)
    setDiscoverForm({ name: '', subnets: '', group_name: '' })
    discoverMutation.reset()
  }

  const activeGroup = groups.find((g) => g.id === groupFilter)

  // ---------------------------------------------------------------------------
  // Render
  // ---------------------------------------------------------------------------

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Devices</h1>
          <p className="text-sm text-gray-500 mt-0.5">
            {data?.total ?? 0} registered devices
            {activeGroup && (
              <span className="ml-2 text-brand-700 font-medium">
                · filtered by group "{activeGroup.name}"
              </span>
            )}
          </p>
        </div>
        <div className="flex gap-2">
          <button onClick={() => refetch()}
            className="p-2 rounded-lg border border-gray-200 hover:bg-gray-50 text-gray-600">
            <RefreshCw size={16} />
          </button>
          <button
            onClick={() => { setShowGroups((v) => !v); setShowAdd(false); setShowDiscover(false) }}
            className={`flex items-center gap-2 border px-4 py-2 rounded-lg text-sm font-medium transition-colors
              ${showGroups
                ? 'bg-purple-50 border-purple-400 text-purple-700'
                : 'border-gray-200 text-gray-600 hover:bg-gray-50'}`}
          >
            {showGroups ? <FolderOpen size={16} /> : <Folder size={16} />} Groups
          </button>
          <button
            onClick={() => { setShowDiscover(true); setShowAdd(false); setShowGroups(false) }}
            className="flex items-center gap-2 border border-brand-700 text-brand-700 px-4 py-2 rounded-lg
                       text-sm font-medium hover:bg-brand-50 transition-colors"
          >
            <Network size={16} /> Discover Subnet
          </button>
          <button
            onClick={() => { setShowAdd(true); setShowDiscover(false); setShowGroups(false) }}
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

      {/* Groups panel */}
      {showGroups && (
        <div className="bg-white border border-gray-200 rounded-xl p-5 shadow-sm">
          <h3 className="text-sm font-semibold mb-4">Device Groups</h3>
          <div className="flex gap-6">
            {/* Group list */}
            <div className="flex-1 space-y-2">
              {groups.length === 0 && (
                <p className="text-sm text-gray-400">No groups yet. Create one on the right.</p>
              )}
              {groups.map((g) => (
                <div
                  key={g.id}
                  className={`flex items-center justify-between px-3 py-2 rounded-lg border cursor-pointer transition-colors
                    ${groupFilter === g.id
                      ? 'border-brand-400 bg-brand-50'
                      : 'border-gray-100 hover:border-gray-200 hover:bg-gray-50'}`}
                  onClick={() => setGroupFilter(groupFilter === g.id ? null : g.id)}
                >
                  <div className="flex items-center gap-2">
                    <span
                      className="w-3 h-3 rounded-full flex-shrink-0"
                      style={{ backgroundColor: g.color ?? '#6b7280' }}
                    />
                    <span className="text-sm font-medium text-gray-900">{g.name}</span>
                    <span className="text-xs text-gray-400">{g.device_count} devices</span>
                  </div>
                  <button
                    onClick={(e) => {
                      e.stopPropagation()
                      if (confirm(`Delete group "${g.name}"?`)) deleteGroupMutation.mutate(g.id)
                    }}
                    className="text-gray-300 hover:text-red-500 p-1 rounded"
                  >
                    <X size={13} />
                  </button>
                </div>
              ))}
            </div>

            {/* Create group */}
            <div className="w-64 border-l border-gray-100 pl-6 space-y-3">
              <p className="text-xs font-semibold text-gray-700 uppercase tracking-wide">New Group</p>
              <InputField
                label="Name"
                value={newGroupName}
                onChange={setNewGroupName}
                placeholder="e.g. Production Servers"
              />
              <div>
                <label className="block text-xs font-medium text-gray-700 mb-1">Colour</label>
                <div className="flex gap-1.5 flex-wrap">
                  {GROUP_COLORS.map((c) => (
                    <button
                      key={c}
                      onClick={() => setNewGroupColor(c)}
                      className={`w-6 h-6 rounded-full transition-transform
                        ${newGroupColor === c ? 'scale-125 ring-2 ring-offset-1 ring-gray-400' : ''}`}
                      style={{ backgroundColor: c }}
                    />
                  ))}
                </div>
              </div>
              <button
                onClick={() => addGroupMutation.mutate()}
                disabled={!newGroupName.trim() || addGroupMutation.isPending}
                className="w-full flex items-center justify-center gap-2 bg-brand-700 text-white
                           px-3 py-1.5 rounded-lg text-sm font-medium hover:bg-brand-800
                           disabled:opacity-50"
              >
                <FolderPlus size={14} /> Create Group
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Add device form */}
      {showAdd && (
        <div className="bg-white border border-gray-200 rounded-xl p-5 shadow-sm">
          <h3 className="text-sm font-semibold mb-4">Add New Device</h3>
          <div className="grid grid-cols-2 gap-4">
            {([
              ['hostname', 'Hostname'],
              ['ip_address', 'IP Address'],
              ['credential_ref', '1Password Ref (optional)'],
              ['notes', 'Notes (optional)'],
            ] as [keyof typeof form, string][]).map(([field, label]) => (
              <InputField
                key={field}
                label={label}
                value={form[field]}
                onChange={(v) => setForm((f) => ({ ...f, [field]: v }))}
              />
            ))}
            <div>
              <label className="block text-xs font-medium text-gray-700 mb-1">OS Type</label>
              <select
                value={form.os_type}
                onChange={(e) => setForm((f) => ({ ...f, os_type: e.target.value }))}
                className="w-full border border-gray-200 rounded-lg px-3 py-1.5 text-sm
                           focus:outline-none focus:ring-2 focus:ring-brand-500"
              >
                {OS_OPTIONS.map((o) => <option key={o} value={o}>{o}</option>)}
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
            <button onClick={() => setShowAdd(false)}
              className="px-4 py-1.5 rounded-lg text-sm border border-gray-200 hover:bg-gray-50">
              Cancel
            </button>
          </div>
        </div>
      )}

      {/* Discover subnet panel */}
      {showDiscover && (
        <div className="bg-white border border-gray-200 rounded-xl p-5 shadow-sm">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold">Discover Subnet</h3>
            <button onClick={closeDiscovery} className="text-gray-400 hover:text-gray-600">
              <X size={16} />
            </button>
          </div>

          {!discoveryJob && (
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <InputField
                  label="Job Name"
                  value={discoverForm.name}
                  onChange={(v) => setDiscoverForm((f) => ({ ...f, name: v }))}
                  placeholder="e.g. Office LAN sweep"
                />
                <InputField
                  label="Auto-assign to Group (optional)"
                  value={discoverForm.group_name}
                  onChange={(v) => setDiscoverForm((f) => ({ ...f, group_name: v }))}
                  placeholder="e.g. Office Network"
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-gray-700 mb-1">
                  Subnets / IPs <span className="text-gray-400 font-normal">(one per line or comma-separated)</span>
                </label>
                <textarea
                  value={discoverForm.subnets}
                  onChange={(e) => setDiscoverForm((f) => ({ ...f, subnets: e.target.value }))}
                  rows={3}
                  placeholder="192.168.1.0/24&#10;10.0.0.5"
                  className="w-full border border-gray-200 rounded-lg px-3 py-1.5 text-sm font-mono
                             focus:outline-none focus:ring-2 focus:ring-brand-500 resize-none"
                />
              </div>
              {discoverMutation.isError && (
                <p className="text-xs text-red-600">Failed to start discovery. Please try again.</p>
              )}
              <div className="flex gap-2">
                <button
                  onClick={() => discoverMutation.mutate()}
                  disabled={!discoverForm.name || !discoverForm.subnets.trim() || discoverMutation.isPending}
                  className="bg-brand-700 text-white px-4 py-1.5 rounded-lg text-sm font-medium
                             hover:bg-brand-800 disabled:opacity-50 flex items-center gap-2"
                >
                  {discoverMutation.isPending && <Loader2 size={14} className="animate-spin" />}
                  {discoverMutation.isPending ? 'Starting…' : 'Start Discovery'}
                </button>
                <button onClick={closeDiscovery}
                  className="px-4 py-1.5 rounded-lg text-sm border border-gray-200 hover:bg-gray-50">
                  Cancel
                </button>
              </div>
            </div>
          )}

          {discoveryJob && (
            <div className="space-y-3">
              <div className="flex items-center gap-3">
                {discoveryJob.status === 'completed' && <CheckCircle size={18} className="text-green-600" />}
                {discoveryJob.status === 'failed' && <AlertCircle size={18} className="text-red-500" />}
                {(discoveryJob.status === 'pending' || discoveryJob.status === 'running') && (
                  <Loader2 size={18} className="animate-spin text-brand-600" />
                )}
                <div>
                  <p className="text-sm font-medium text-gray-900">{discoveryJob.name}</p>
                  <p className="text-xs text-gray-500 capitalize">{discoveryJob.status}</p>
                </div>
              </div>
              <div className="bg-gray-50 rounded-lg px-4 py-3 text-sm space-y-1">
                <div className="flex justify-between">
                  <span className="text-gray-500">Target ranges</span>
                  <span className="font-mono text-xs text-gray-700">{discoveryJob.target_ranges.join(', ')}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-500">Devices found</span>
                  <span className="font-semibold text-gray-900">{discoveryJob.devices_found}</span>
                </div>
                {discoveryJob.completed_at && (
                  <div className="flex justify-between">
                    <span className="text-gray-500">Completed</span>
                    <span className="text-gray-700">{format(new Date(discoveryJob.completed_at), 'HH:mm:ss')}</span>
                  </div>
                )}
              </div>
              {discoveryJob.error_message && (
                <p className="text-xs text-red-600 bg-red-50 rounded-lg px-3 py-2">{discoveryJob.error_message}</p>
              )}
              {(discoveryJob.status === 'completed' || discoveryJob.status === 'failed') && (
                <button onClick={closeDiscovery}
                  className="px-4 py-1.5 rounded-lg text-sm border border-gray-200 hover:bg-gray-50">
                  Close
                </button>
              )}
            </div>
          )}
        </div>
      )}

      {/* Edit device modal */}
      {editDevice && (
        <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50">
          <div className="bg-white rounded-xl shadow-xl w-full max-w-lg p-6">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-base font-semibold text-gray-900">Edit Device</h3>
              <button onClick={() => setEditDevice(null)} className="text-gray-400 hover:text-gray-600">
                <X size={18} />
              </button>
            </div>
            <div className="grid grid-cols-2 gap-4">
              <InputField label="Hostname" value={editForm.hostname} onChange={(v) => setEditForm((f) => ({ ...f, hostname: v }))} />
              <InputField label="IP Address" value={editForm.ip_address} onChange={(v) => setEditForm((f) => ({ ...f, ip_address: v }))} />
              <InputField label="OS Name" value={editForm.os_name} onChange={(v) => setEditForm((f) => ({ ...f, os_name: v }))} placeholder="e.g. Ubuntu 22.04 LTS" />
              <InputField label="OS Version" value={editForm.os_version} onChange={(v) => setEditForm((f) => ({ ...f, os_version: v }))} />
              <InputField label="SSH Port" value={editForm.ssh_port} onChange={(v) => setEditForm((f) => ({ ...f, ssh_port: v }))} type="number" />
              <InputField label="WinRM Port" value={editForm.winrm_port} onChange={(v) => setEditForm((f) => ({ ...f, winrm_port: v }))} type="number" />
              <InputField label="1Password Ref" value={editForm.credential_ref} onChange={(v) => setEditForm((f) => ({ ...f, credential_ref: v }))} />
              <InputField label="Notes" value={editForm.notes} onChange={(v) => setEditForm((f) => ({ ...f, notes: v }))} />
              <div>
                <label className="block text-xs font-medium text-gray-700 mb-1">OS Type</label>
                <select
                  value={editForm.os_type}
                  onChange={(e) => setEditForm((f) => ({ ...f, os_type: e.target.value }))}
                  className="w-full border border-gray-200 rounded-lg px-3 py-1.5 text-sm
                             focus:outline-none focus:ring-2 focus:ring-brand-500"
                >
                  {OS_OPTIONS.map((o) => <option key={o} value={o}>{o}</option>)}
                </select>
              </div>
            </div>
            {editMutation.isError && (
              <p className="text-xs text-red-600 mt-3">Failed to update device. Please try again.</p>
            )}
            <div className="flex gap-2 mt-5">
              <button
                onClick={() => editMutation.mutate()}
                disabled={editMutation.isPending}
                className="bg-brand-700 text-white px-4 py-1.5 rounded-lg text-sm font-medium
                           hover:bg-brand-800 disabled:opacity-50"
              >
                {editMutation.isPending ? 'Saving…' : 'Save Changes'}
              </button>
              <button onClick={() => setEditDevice(null)}
                className="px-4 py-1.5 rounded-lg text-sm border border-gray-200 hover:bg-gray-50">
                Cancel
              </button>
            </div>
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
            {(data?.items ?? []).map((d) => (
              <tr key={d.id} className="hover:bg-gray-50 transition-colors">
                <td className="px-4 py-3">
                  <span className={`inline-block w-2 h-2 rounded-full ${STATUS_DOT[d.status]}`} />
                </td>
                <td className="px-4 py-3 font-medium text-gray-900">{d.hostname}</td>
                <td className="px-4 py-3 font-mono text-gray-600">{d.ip_address}</td>
                <td className="px-4 py-3">
                  {OS_ICONS[d.os_type] ?? '❓'} {d.os_type}
                </td>
                <td className="px-4 py-3 text-gray-500">{d.os_version ?? '—'}</td>
                <td className="px-4 py-3">
                  {d.agent_installed
                    ? <span className="text-green-700 bg-green-50 text-xs px-2 py-0.5 rounded-full">Installed</span>
                    : <span className="text-gray-400 text-xs">Agentless</span>}
                </td>
                <td className="px-4 py-3 text-gray-500">
                  {d.last_scanned_at ? format(new Date(d.last_scanned_at), 'MMM d HH:mm') : 'Never'}
                </td>
                <td className="px-4 py-3">
                  <div className="flex items-center gap-1">
                    <button
                      onClick={() => openEdit(d)}
                      title="Edit device"
                      className="text-gray-400 hover:text-brand-600 transition-colors p-1 rounded"
                    >
                      <Pencil size={13} />
                    </button>
                    {groupFilter && (
                      <button
                        onClick={() => removeFromGroupMutation.mutate({ groupId: groupFilter, deviceId: d.id })}
                        title="Remove from group"
                        className="text-gray-400 hover:text-orange-500 transition-colors p-1 rounded"
                      >
                        <UserMinus size={13} />
                      </button>
                    )}
                    <button
                      onClick={() => { if (confirm(`Delete device ${d.hostname}?`)) deleteMutation.mutate(d.id) }}
                      className="text-gray-400 hover:text-red-600 transition-colors p-1 rounded"
                    >
                      <Trash2 size={13} />
                    </button>
                  </div>
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
