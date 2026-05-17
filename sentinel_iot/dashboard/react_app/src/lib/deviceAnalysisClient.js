import axios from 'axios'

export const DEVICE_ANALYSIS_SECTIONS = ['risk_explanation', 'anomaly_summary', 'next_actions']

const analysisCache = new Map()
const analysisInflight = new Map()

export const peekDeviceAnalysis = (deviceIp) => {
  if (!deviceIp) {
    return null
  }

  return analysisCache.get(`${deviceIp}:${DEVICE_ANALYSIS_SECTIONS.join(',')}:`) || null
}

export const clearDeviceAnalysis = (deviceIp) => {
  if (!deviceIp) {
    return
  }

  Array.from(analysisCache.keys()).forEach((key) => {
    if (key === deviceIp || key.startsWith(`${deviceIp}:`)) {
      analysisCache.delete(key)
    }
  })
}

export const clearAllDeviceAnalysis = () => {
  analysisCache.clear()
}

export const fetchDeviceAnalysis = async ({
  apiBaseUrl,
  deviceIp,
  forceRefresh = false,
  timeout = 25000,
  includeSections = DEVICE_ANALYSIS_SECTIONS,
  userQuestion = null,
  conversationHistory = []
}) => {
  if (!deviceIp) {
    throw new Error('deviceIp is required')
  }

  const cacheKey = `${deviceIp}:${(includeSections || []).join(',')}:${userQuestion || ''}`

  if (!forceRefresh) {
    const cached = analysisCache.get(cacheKey)
    if (cached) {
      return cached
    }

    const inflight = analysisInflight.get(cacheKey)
    if (inflight) {
      return inflight
    }
  }

  const request = axios.post(
    `${apiBaseUrl}/llm/device-analysis`,
    {
      device_ip: deviceIp,
      include_sections: includeSections,
      user_question: userQuestion,
      conversation_history: conversationHistory
    },
    { timeout }
  )
    .then((response) => {
      analysisCache.set(cacheKey, response.data)
      return response.data
    })
    .finally(() => {
      const active = analysisInflight.get(cacheKey)
      if (active === request) {
        analysisInflight.delete(cacheKey)
      }
    })

  analysisInflight.set(cacheKey, request)
  return request
}
