import { Outlet } from 'react-router-dom'
import Sidebar from './Sidebar'
import TopBar from './TopBar'
import { useState } from 'react'

export default function Layout() {
  const [sidebarOpen, setSidebarOpen] = useState(true)

  return (
    <div style={{ display: 'flex', height: '100vh', overflow: 'hidden' }}>
      {/* Sidebar — in-flow, not fixed */}
      <Sidebar open={sidebarOpen} onToggle={() => setSidebarOpen(o => !o)} />

      {/* Right column: TopBar + page content */}
      <div style={{
        flex: 1,
        display: 'flex',
        flexDirection: 'column',
        overflow: 'hidden',
        background: 'var(--bg-primary)',
        minWidth: 0,
      }}>
        <TopBar />
        <div style={{ flex: 1, overflow: 'hidden' }}>
          <Outlet />
        </div>
      </div>
    </div>
  )
}
