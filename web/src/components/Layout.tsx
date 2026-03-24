import { Outlet, NavLink, useNavigate } from 'react-router-dom'
import {
  LayoutDashboard, Monitor, ScanSearch, ShieldAlert,
  FileSearch, LogOut,
} from 'lucide-react'
import { clsx } from 'clsx'

const navItems = [
  { to: '/dashboard',       label: 'Dashboard',       icon: LayoutDashboard },
  { to: '/devices',         label: 'Devices',         icon: Monitor },
  { to: '/scans',           label: 'Scans',            icon: ScanSearch },
  { to: '/vulnerabilities', label: 'Vulnerabilities', icon: ShieldAlert },
  { to: '/findings',        label: 'Findings',        icon: FileSearch },
]

export default function Layout() {
  const navigate = useNavigate()

  function handleLogout() {
    localStorage.removeItem('token')
    navigate('/login')
  }

  return (
    <div className="flex h-screen bg-gray-50">
      {/* Sidebar */}
      <aside className="w-64 bg-brand-900 text-white flex flex-col">
        <div className="px-6 py-5 border-b border-brand-800">
          <div className="flex items-center gap-2">
            <ShieldAlert className="text-brand-100" size={22} />
            <span className="text-lg font-semibold tracking-tight">Claude Scanner</span>
          </div>
          <p className="text-xs text-brand-300 mt-0.5">Enterprise Vulnerability Management</p>
        </div>

        <nav className="flex-1 py-4 px-3 space-y-0.5">
          {navItems.map(({ to, label, icon: Icon }) => (
            <NavLink
              key={to}
              to={to}
              className={({ isActive }) =>
                clsx(
                  'flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition-colors',
                  isActive
                    ? 'bg-brand-700 text-white'
                    : 'text-brand-200 hover:bg-brand-800 hover:text-white',
                )
              }
            >
              <Icon size={17} />
              {label}
            </NavLink>
          ))}
        </nav>

        <div className="px-3 py-4 border-t border-brand-800">
          <button
            onClick={handleLogout}
            className="flex items-center gap-3 w-full px-3 py-2 rounded-lg text-sm text-brand-200
                       hover:bg-brand-800 hover:text-white transition-colors"
          >
            <LogOut size={17} />
            Sign out
          </button>
        </div>
      </aside>

      {/* Main content */}
      <main className="flex-1 flex flex-col overflow-hidden">
        <div className="flex-1 overflow-y-auto p-6">
          <Outlet />
        </div>
      </main>
    </div>
  )
}
