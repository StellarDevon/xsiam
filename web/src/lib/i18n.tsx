import { createContext, useContext, useState } from 'react'

export type Lang = 'en' | 'zh'

const LangContext = createContext<{ lang: Lang; setLang: (l: Lang) => void }>({
  lang: 'zh',
  setLang: () => {},
})

export function I18nProvider({ children }: { children: React.ReactNode }) {
  const [lang, setLangState] = useState<Lang>(() => {
    return (localStorage.getItem('xsiam-lang') as Lang) ?? 'zh'
  })

  function setLang(l: Lang) {
    setLangState(l)
    localStorage.setItem('xsiam-lang', l)
  }

  return <LangContext.Provider value={{ lang, setLang }}>{children}</LangContext.Provider>
}

export function useLang() {
  return useContext(LangContext)
}

// ── Full UI dictionary — TopBar, Sidebar nav, page titles, common labels ──────
const dict: Record<Lang, Record<string, string>> = {
  zh: {
    // TopBar
    search_placeholder: '搜索告警、事件、资产…',
    notifications: '通知',
    mark_all_read: '全部已读',
    view_all_alerts: '查看全部告警 →',
    alerts_tab: '告警',
    system_tab: '系统',
    no_alerts: '暂无告警通知',
    quick_nav: '快捷导航',
    recent_search: '最近搜索',
    search_results: '搜索结果',
    no_results: '未找到匹配的告警',
    esc_close: 'ESC 关闭',
    session_expiring: '即将过期',
    session_remain: '会话剩余',
    renew: '续期会话',
    logout: '退出登录',
    settings: '系统设置',
    switch_theme: '切换主题',
    dark: '暗色',
    light: '亮色',
    new_notifications: '条新通知',
    // Sidebar nav items
    nav_overview: '概览',
    nav_incidents: '事件',
    nav_alerts: '告警',
    nav_causality: '溯源图',
    nav_query: '查询中心',
    nav_actions: '动作中心',
    nav_playbooks: '剧本',
    nav_assets: '资产',
    nav_identity_risks: '身份风险',
    nav_vulnerabilities: '漏洞',
    nav_exposure: '暴露面管理',
    nav_threat_intel: '威胁情报',
    nav_iocs: 'IOC 管理',
    nav_agentix: 'Agentix',
    nav_cases: '案件',
    nav_devices: '设备',
    nav_agents_hub: 'Agent 中心',
    nav_detection_rules: '检测规则',
    nav_etl: 'ETL 流水线',
    nav_network: '网络安全',
    nav_endpoint: '终端安全',
    nav_tenant: '租户管理',
    nav_reports: '报表',
    // Group labels
    grp_response: '响应',
    grp_assets: '资产与风险',
    grp_threat: '威胁情报',
    grp_aiops: 'AI',
    grp_infra: '基础设施',
    grp_platform: '平台管理',
    // Common page labels
    loading: '加载中…',
    no_data: '暂无数据',
    save: '保存',
    cancel: '取消',
    delete: '删除',
    edit: '编辑',
    create: '新建',
    search: '搜索',
    filter: '筛选',
    export: '导出',
    refresh: '刷新',
    confirm: '确认',
    close: '关闭',
  },
  en: {
    // TopBar
    search_placeholder: 'Search alerts, incidents, assets…',
    notifications: 'Notifications',
    mark_all_read: 'Mark all read',
    view_all_alerts: 'View all alerts →',
    alerts_tab: 'Alerts',
    system_tab: 'System',
    no_alerts: 'No alert notifications',
    quick_nav: 'Quick navigation',
    recent_search: 'Recent searches',
    search_results: 'Search results',
    no_results: 'No matching alerts found',
    esc_close: 'ESC close',
    session_expiring: 'Expiring soon',
    session_remain: 'Session',
    renew: 'Renew session',
    logout: 'Sign out',
    settings: 'System Settings',
    switch_theme: 'Toggle theme',
    dark: 'Dark',
    light: 'Light',
    new_notifications: 'new notifications',
    // Sidebar nav items
    nav_overview: 'Overview',
    nav_incidents: 'Incidents',
    nav_alerts: 'Alerts',
    nav_causality: 'Causality Graph',
    nav_query: 'Query Center',
    nav_actions: 'Actions',
    nav_playbooks: 'Playbooks',
    nav_assets: 'Assets',
    nav_identity_risks: 'Identity Risks',
    nav_vulnerabilities: 'Vulnerabilities',
    nav_exposure: 'Exposure Mgmt',
    nav_threat_intel: 'Threat Intel',
    nav_iocs: 'IOC Management',
    nav_agentix: 'Agentix',
    nav_cases: 'Cases',
    nav_devices: 'Devices',
    nav_agents_hub: 'Agent Hub',
    nav_detection_rules: 'Detection Rules',
    nav_etl: 'ETL Pipeline',
    nav_network: 'Network Security',
    nav_endpoint: 'Endpoint Security',
    nav_tenant: 'Tenant Admin',
    nav_reports: 'Reports',
    // Group labels
    grp_response: 'Response',
    grp_assets: 'Assets & Risk',
    grp_threat: 'Threat Intel',
    grp_aiops: 'AI',
    grp_infra: 'Infrastructure',
    grp_platform: 'Platform',
    // Common page labels
    loading: 'Loading…',
    no_data: 'No data',
    save: 'Save',
    cancel: 'Cancel',
    delete: 'Delete',
    edit: 'Edit',
    create: 'New',
    search: 'Search',
    filter: 'Filter',
    export: 'Export',
    refresh: 'Refresh',
    confirm: 'Confirm',
    close: 'Close',
  },
}

export function useT() {
  const { lang } = useLang()
  // Returns a stable-enough translator — re-created each render when lang changes
  return (key: string): string => dict[lang]?.[key] ?? dict['zh'][key] ?? key
}
