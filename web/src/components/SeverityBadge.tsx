import { clsx } from 'clsx'
import type { Severity } from '../types'

const config: Record<Severity, { label: string; className: string }> = {
  critical: { label: 'Critical', className: 'bg-red-100 text-red-800' },
  high:     { label: 'High',     className: 'bg-orange-100 text-orange-800' },
  medium:   { label: 'Medium',   className: 'bg-yellow-100 text-yellow-800' },
  low:      { label: 'Low',      className: 'bg-green-100 text-green-800' },
  none:     { label: 'None',     className: 'bg-gray-100 text-gray-600' },
  unknown:  { label: 'Unknown',  className: 'bg-gray-100 text-gray-500' },
}

export default function SeverityBadge({ severity }: { severity: Severity }) {
  const { label, className } = config[severity] ?? config.unknown
  return (
    <span className={clsx('inline-flex items-center px-2 py-0.5 rounded text-xs font-medium', className)}>
      {label}
    </span>
  )
}
