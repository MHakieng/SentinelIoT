export const safeNumber = (value, fallback = 0) => {
  const numeric = Number(value)
  return Number.isFinite(numeric) ? numeric : fallback
}

export const clampPercent = (value) => Math.min(100, Math.max(0, safeNumber(value)))

export const getFlowMlScore = (flow = {}) => {
  const rawScore = flow.ml_anomaly_score ?? flow.anomaly_score ?? flow.attack_probability
  return clampPercent(safeNumber(rawScore) * 100)
}

export const getFlowFinalRisk = (flow = {}) => (
  clampPercent(flow.final_flow_risk ?? getFlowMlScore(flow))
)

export const getFlowSeverity = (flow = {}) => {
  const severity = String(flow.severity || '').toLowerCase()
  if (['low', 'medium', 'high', 'critical'].includes(severity)) return severity

  const risk = getFlowFinalRisk(flow)
  if (risk >= 80) return 'critical'
  if (risk >= 60) return 'high'
  if (risk >= 35) return 'medium'
  return 'low'
}

export const isBackendAnomaly = (flow = {}) => (
  flow.label === 1 || flow.is_anomaly === true || flow.decision === 'anomaly'
)

export const isModelFlaggedFlow = (flow = {}) => (
  isBackendAnomaly(flow) || safeNumber(flow.ml_anomaly_score ?? flow.anomaly_score ?? flow.attack_probability) >= 0.5
)

export const isHighRiskFlow = (flow = {}) => getFlowFinalRisk(flow) >= 60

export const getFlowDisplayStatus = (flow = {}) => {
  if (isBackendAnomaly(flow)) return 'model anomaly'
  if (isHighRiskFlow(flow)) return 'high risk'
  return 'observed'
}
