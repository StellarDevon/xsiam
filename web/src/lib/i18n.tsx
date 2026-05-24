import { createContext, useContext, useState } from 'react'

export type Lang = 'en' | 'zh'

const LangContext = createContext<{ lang: Lang; setLang: (l: Lang) => void }>({
  lang: 'en',
  setLang: () => {},
})

export function I18nProvider({ children }: { children: React.ReactNode }) {
  const [lang, setLangState] = useState<Lang>(() => {
    return (localStorage.getItem('xsiam-lang') as Lang) ?? 'en'
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

// ── 通用 UI 字典（仅用于 TopBar 和全局级别的可见标签）
const dict: Record<string, Record<string, string>> = {
  zh: {
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
    settings: '个人设置',
    switch_theme: '切换主题',
    dark: '暗色',
    light: '亮色',
    new_notifications: '条新通知',
  },
  en: {
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
    settings: 'Settings',
    switch_theme: 'Toggle theme',
    dark: 'Dark',
    light: 'Light',
    new_notifications: 'new notifications',
  },
}

export function useT() {
  const { lang } = useLang()
  return (key: string) => dict[lang]?.[key] ?? dict['zh'][key] ?? key
}
