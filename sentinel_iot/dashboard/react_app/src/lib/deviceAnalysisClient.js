import axios from 'axios'

export const DEVICE_ANALYSIS_SECTIONS = ['risk_explanation', 'anomaly_summary', 'next_actions']

const analysisCache = new Map()
const analysisInflight = new Map()

export const peekDeviceAnalysis = (deviceIp) => {
  if (!deviceIp) {
    return null
  }

  return analysisCache.get(deviceIp) || null
}

export const clearDeviceAnalysis = (deviceIp) => {
  if (!deviceIp) {
    return
  }

  analysisCache.delete(deviceIp)
}

export const clearAllDeviceAnalysis = () => {
  analysisCache.clear()
}

export const fetchDeviceAnalysis = async ({ apiBaseUrl, deviceIp, forceRefresh = false, timeout = 25000 }) => {
  if (!deviceIp) {
    throw new Error('deviceIp is required')
  }

  if (!forceRefresh) {
    const cached = analysisCache.get(deviceIp)
    if (cached) {
      return cached
    }

    const inflight = analysisInflight.get(deviceIp)
    if (inflight) {
      return inflight
    }
  }

  const request = axios.post(
    `${apiBaseUrl}/llm/device-analysis`,
    {
      device_ip: deviceIp,
      include_sections: DEVICE_ANALYSIS_SECTIONS
    },
    { timeout }
  )
    .then((response) => {
      analysisCache.set(deviceIp, response.data)
      return response.data
    })
    .finally(() => {
      const active = analysisInflight.get(deviceIp)
      if (active === request) {
        analysisInflight.delete(deviceIp)
      }
    })

  analysisInflight.set(deviceIp, request)
  return request
}
