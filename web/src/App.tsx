import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { isAuthenticated } from '@/lib/auth'
import { ThemeProvider } from '@/lib/theme'
import { I18nProvider } from '@/lib/i18n'
import Layout from '@/components/Layout'
import Login from '@/pages/Login'
import Dashboard from '@/pages/Dashboard'
import Incidents from '@/pages/Incidents'
import Alerts from '@/pages/Alerts'
import Assets from '@/pages/Assets'
import ThreatIntel from '@/pages/ThreatIntel'
import IOCs from '@/pages/IOCs'
import Devices from '@/pages/Devices'
import DetectionRules from '@/pages/DetectionRules'
import Playbooks from '@/pages/Playbooks'
import Actions from '@/pages/Actions'
import Vulnerabilities from '@/pages/Vulnerabilities'
import ExposureScores from '@/pages/ExposureScores'
import IdentityRisks from '@/pages/IdentityRisks'
import CausalityGraph from '@/pages/CausalityGraph'
import Reports from '@/pages/Reports'
import QueryCenter from '@/pages/QueryCenter'
import Settings from '@/pages/Settings'
import AgentsHub from '@/pages/AgentsHub'
import Agentix from '@/pages/Agentix'
import XSIAMCases from '@/pages/XSIAMCases'

function RequireAuth({ children }: { children: React.ReactNode }) {
  return isAuthenticated() ? <>{children}</> : <Navigate to="/login" replace />
}

export default function App() {
  return (
    <ThemeProvider>
    <I18nProvider>
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/" element={<RequireAuth><Layout /></RequireAuth>}>
          <Route index element={<Dashboard />} />
          <Route path="incidents" element={<Incidents />} />
          <Route path="alerts" element={<Alerts />} />
          <Route path="causality" element={<CausalityGraph />} />
          <Route path="assets" element={<Assets />} />
          <Route path="threat-intel" element={<ThreatIntel />} />
          <Route path="iocs" element={<IOCs />} />
          <Route path="intel-feeds" element={<ThreatIntel />} />
          <Route path="vulnerabilities" element={<Vulnerabilities />} />
          <Route path="exposure" element={<ExposureScores />} />
          <Route path="identity-risks" element={<IdentityRisks />} />
          <Route path="devices" element={<Devices />} />
          <Route path="agents-hub" element={<AgentsHub />} />
          <Route path="detection-rules" element={<DetectionRules />} />
          <Route path="playbooks" element={<Playbooks />} />
          <Route path="actions" element={<Actions />} />
          <Route path="reports" element={<Reports />} />
          <Route path="query" element={<QueryCenter />} />
          <Route path="settings" element={<Settings />} />
          <Route path="agentix" element={<Agentix />} />
          <Route path="xsiam-cases" element={<XSIAMCases />} />
        </Route>
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
    </I18nProvider>
    </ThemeProvider>
  )
}
