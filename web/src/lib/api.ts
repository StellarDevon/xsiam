import axios from 'axios'

const api = axios.create({ baseURL: '/api' })

api.interceptors.request.use(cfg => {
  const token = localStorage.getItem('token')
  if (token) cfg.headers.Authorization = `Bearer ${token}`
  return cfg
})

api.interceptors.response.use(
  r => r,
  err => {
    if (err.response?.status === 401) {
      localStorage.removeItem('token')
      window.location.href = '/login'
    }
    return Promise.reject(err)
  }
)

export default api

export interface PageMeta { page: number; page_size: number; total: number; total_pages: number }
export interface ListResp<T> { data: { items: T[]; meta: PageMeta }; success: boolean }
export interface ItemResp<T> { data: T; success: boolean }
