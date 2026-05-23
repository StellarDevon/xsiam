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
