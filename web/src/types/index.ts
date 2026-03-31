export interface User {
  id: string
  username: string
  email: string
  full_name: string | null
  is_active: boolean
  is_admin: boolean
  created_at: string
}

export type OSType = 'linux' | 'windows' | 'darwin' | 'unix' | 'ibmi' | 'unknown'
export type DeviceStatus = 'online' | 'offline' | 'unknown'

export interface Device {
  id: string
  hostname: string
  ip_address: string
  os_type: OSType
  os_name: string | null
  os_version: string | null
  architecture: string | null
  kernel_version: string | null
  ssh_port: number
  winrm_port: number
  credential_ref: string | null
  agent_installed: boolean
  agent_version: string | null
  agent_last_seen: string | null
  tags: Record<string, string>
  status: DeviceStatus
  notes: string | null
  created_at: string
  updated_at: string
  last_scanned_at: string | null
}

export interface DeviceListResponse {
  items: Device[]
  total: number
  page: number
  page_size: number
}

export type ScanStatus = 'pending' | 'running' | 'completed' | 'failed' | 'cancelled'
export type ScanType = 'full' | 'network' | 'packages' | 'config' | 'quick'

export interface ScanTarget {
  id: string
  device_id: string
  status: ScanStatus
  started_at: string | null
  completed_at: string | null
  error_message: string | null
}

export interface ScanJob {
  id: string
  name: string
  scan_type: ScanType
  status: ScanStatus
  total_devices: number
  completed_devices: number
  failed_devices: number
  created_at: string
  started_at: string | null
  completed_at: string | null
  created_by: string
  targets?: ScanTarget[]
}

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'none' | 'unknown'
export type FindingStatus = 'open' | 'acknowledged' | 'false_positive' | 'resolved'
export type FindingType = 'package' | 'network' | 'config'

export interface Vulnerability {
  id: string
  source: string
  title: string | null
  description: string | null
  severity: Severity
  cvss_v3_score: number | null
  cvss_v3_vector: string | null
  cvss_v2_score: number | null
  cwe_ids: string[]
  published_at: string | null
  modified_at: string | null
  epss_score: number | null
  epss_percentile: number | null
}

export interface Finding {
  id: string
  device_id: string
  vulnerability_id: string
  finding_type: FindingType
  status: FindingStatus
  severity: Severity
  affected_component: string | null
  affected_version: string | null
  fixed_version: string | null
  epss_score: number | null
  epss_percentile: number | null
  cvss_score: number | null
  first_seen: string
  last_seen: string
  resolved_at: string | null
  notes: string | null
}

export interface DiscoveryJob {
  id: string
  name: string
  target_ranges: string[]
  status: ScanStatus
  devices_found: number
  created_at: string
  completed_at: string | null
  error_message: string | null
}

export interface DeviceGroup {
  id: string
  name: string
  description: string | null
  color: string | null
  device_count: number
  created_at: string
  updated_at: string
}

export interface DeviceTreeGroup {
  id: string
  name: string
  color: string | null
  devices: Device[]
}

export interface DeviceTree {
  groups: DeviceTreeGroup[]
  ungrouped: Device[]
}

export interface FindingSummary {
  total: number
  critical: number
  high: number
  medium: number
  low: number
  open: number
  acknowledged: number
  false_positive: number
  resolved: number
}
