import axios from 'axios'

const BASE_URL = import.meta.env.VITE_API_URL ?? '/api'

export const api = axios.create({
  baseURL: BASE_URL,
  headers: { 'Content-Type': 'application/json' },
})

// Attach JWT from localStorage on every request
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

// Redirect to login on 401
api.interceptors.response.use(
  (r) => r,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('token')
      window.location.href = '/login'
    }
    return Promise.reject(error)
  },
)

// --- Auth ---
export const login = (username: string, password: string) =>
  api.post<{ access_token: string }>('/auth/token', new URLSearchParams({ username, password }), {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  })

export const getMe = () => api.get('/auth/me')

// --- Devices ---
export const listDevices = (params?: Record<string, unknown>) =>
  api.get('/devices', { params })

export const getDevice = (id: string) => api.get(`/devices/${id}`)

export const createDevice = (data: Record<string, unknown>) =>
  api.post('/devices', data)

export const updateDevice = (id: string, data: Record<string, unknown>) =>
  api.patch(`/devices/${id}`, data)

export const deleteDevice = (id: string) => api.delete(`/devices/${id}`)

export const bulkImportDevices = (rows: unknown[]) =>
  api.post('/devices/bulk-import', rows)

// --- Scans ---
export const listScans = (params?: Record<string, unknown>) =>
  api.get('/scans', { params })

export const getScan = (id: string) => api.get(`/scans/${id}`)

export const createScan = (data: Record<string, unknown>) =>
  api.post('/scans', data)

export const cancelScan = (id: string) => api.post(`/scans/${id}/cancel`)

export const createDiscovery = (data: Record<string, unknown>) =>
  api.post('/scans/discovery', data)

// --- Vulnerabilities ---
export const listVulnerabilities = (params?: Record<string, unknown>) =>
  api.get('/vulnerabilities', { params })

export const getVulnerability = (id: string) =>
  api.get(`/vulnerabilities/${id}`)

export const getFindingsSummary = () => api.get('/vulnerabilities/summary')

export const listFindings = (params?: Record<string, unknown>) =>
  api.get('/vulnerabilities/findings', { params })

export const updateFinding = (id: string, data: Record<string, unknown>) =>
  api.patch(`/vulnerabilities/findings/${id}`, data)

export const getTopEpssFindings = (limit = 20) =>
  api.get('/vulnerabilities/top-epss', { params: { limit } })

// --- Reports ---
export const downloadFindingsCsv = (params?: Record<string, unknown>) =>
  api.get('/reports/findings/csv', { params, responseType: 'blob' })

export const downloadScanPdf = (scanId: string) =>
  api.get(`/reports/scans/${scanId}/pdf`, { responseType: 'blob' })
