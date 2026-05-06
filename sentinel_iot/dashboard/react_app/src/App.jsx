import React, { useEffect, useRef, useState } from 'react'
import {
  Shield,
  Activity,
  Database,
  AlertTriangle,
  Zap,
  LayoutDashboard,
  Loader2,
  BarChart3,
  Info,
  List,
  Waves,
  Share2,
  CheckCircle2,
  Clock3,
  Sparkles
} from 'lucide-react'
import axios from 'axios'

import InventoryView from './components/InventoryView'
import VulnerabilityView from './components/VulnerabilityView'
import AnomalyView from './components/AnomalyView'
import DeviceDetailView from './components/DeviceDetailView'
import PacketListView from './components/PacketListView'
import FlowSummaryView from './components/FlowSummaryView'
import TopologyView from './components/TopologyView'
import SecurityAssistantPanel from './components/SecurityAssistantPanel'
import { clearAllDeviceAnalysis } from './lib/deviceAnalysisClient'

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8000'

const EMPTY_TOPOLOGY = { nodes: [], links: [] }
const API_ENDPOINTS = {
  devices: '/devices',
  metrics: '/metrics',
  scanStatus: '/scanner/status',
  scanJobs: '/scanner/jobs',
  scans: '/scanner/scans',
  monitorPackets: '/monitor/packets',
  monitorFlows: '/monitor/flows',
  monitorHistory: '/monitor/history',
  monitorTopology: '/monitor/topology',
  monitorLiveStart: '/monitor/live/start',
  monitorLiveStatus: '/monitor/live/status',
  monitorLiveStop: '/monitor/live/stop',
}
const DEVICE_REFRESH_MS = 15000
const METRICS_REFRESH_MS = 20000
const TRAFFIC_REFRESH_MS = 4000
const HISTORY_REFRESH_MS = 10000
const DEFAULT_TOPOLOGY_REFRESH_MS = 10000
const MONITOR_STATUS_REFRESH_MS = 2500
const SCAN_STATUS_REFRESH_MS = 1200
const LIVE_CAPTURE_WINDOW_SECONDS = 10
const NBAIOT_BENCHMARK_ROWS = [
  { model: 'Random Forest', accuracy: 0.999989, precision: 1.0, recall: 0.999988, f1: 0.999994, fpr: 0.0, fnr: 0.000012 },
  { model: 'Extra Trees', accuracy: 0.999983, precision: 1.0, recall: 0.999981, f1: 0.999991, fpr: 0.0, fnr: 0.000019 },
  { model: 'HistGradientBoosting', accuracy: 0.999977, precision: 0.999997, recall: 0.999978, f1: 0.999987, fpr: 0.000029, fnr: 0.000022 },
  { model: 'Balanced RF', accuracy: 0.999913, precision: 1.0, recall: 0.999826, f1: 0.999913, fpr: 0.0, fnr: 0.000174 },
  { model: 'Device Split RF', accuracy: 0.998539, precision: 0.998419, recall: 0.999993, f1: 0.999206, fpr: 0.017886, fnr: 0.000007 },
  { model: 'Isolation Forest 0.15', accuracy: 0.985236, precision: 0.98407, recall: 0.999827, f1: 0.991886, fpr: 0.149999, fnr: 0.000172 },
  { model: 'Device + Attack Split RF', accuracy: 0.761298, precision: 0.994123, recall: 0.685407, f1: 0.806298, fpr: 0.01103, fnr: 0.314593 },
  { model: 'Attack Split RF', accuracy: 0.760342, precision: 1.0, recall: 0.680457, f1: 0.803536, fpr: 0.0, fnr: 0.319543 },
]
const NBAIOT_KEY_FINDINGS = {
  sampleCount: '1,772,641',
  featureCount: 115,
  normalCount: '172,641',
  anomalyCount: '1,600,000',
  randomForestF1: 0.999994,
  balancedRfF1: 0.999913,
  deviceSplitF1: 0.999206,
  attackSplitF1: 0.803536,
  deviceAttackSplitF1: 0.806298,
  bestIsolationContamination: '0.15',
  bestIsolationF1: 0.991886,
  deviceSplitFpr: 0.017886,
  leakageFeature: 'HH_jit_L0.01_mean',
  leakageFeatureF1: 0.958079,
}

const describeRequestFailure = (err, fallback) => {
  if (!err) {
    return fallback
  }

  if (err.code === 'ECONNABORTED') {
    return 'İstek zaman aşımına uğradı. Backend meşgul veya erişilemez olabilir.'
  }

  if (!err.response) {
    return 'Backend erişilemiyor. API sunucusunun çalıştığını kontrol edin.'
  }

  if (err.response.status >= 500) {
    return 'Backend iç hata döndürdü. Ayrıntılar için API terminalini kontrol edin.'
  }

  if (typeof err.response.data?.detail === 'string') {
    return err.response.data.detail
  }

  return fallback
}

const formatFalsePositiveRate = (summary) => {
  const falsePositives = Number(summary?.false_positives || 0)
  const truePositives = Number(summary?.true_positives || 0)

  if (falsePositives === 0 && truePositives === 0) {
    return '0.0%'
  }

  if (truePositives === 0) {
    return 'Yok'
  }

  return `${((falsePositives / truePositives) * 100).toFixed(1)}%`
}

const formatJobFailure = (job) => {
  if (!job) {
    return 'Bilinmeyen tarama hatası.'
  }

  if (job.error) {
    return job.error
  }

  if (typeof job.result === 'string') {
    return job.result
  }

  if (job.message) {
    return job.message
  }

  return 'Tarama başarısız oldu.'
}

const App = () => {
  const [activeTab, setActiveTab] = useState('inventory')
  const [devices, setDevices] = useState([])
  const [selectedDevice, setSelectedDevice] = useState(null)
  const [assistantOpen, setAssistantOpen] = useState(false)

  const [scanLoading, setScanLoading] = useState(false)
  const [scanProgress, setScanProgress] = useState(0)
  const [scanError, setScanError] = useState(null)
  const [scanNotice, setScanNotice] = useState(null)

  const [devicesLoading, setDevicesLoading] = useState(true)
  const [devicesError, setDevicesError] = useState(null)

  const [systemMetrics, setSystemMetrics] = useState(null)
  const [metricsLoading, setMetricsLoading] = useState(true)
  const [metricsError, setMetricsError] = useState(null)

  const [livePackets, setLivePackets] = useState([])
  const [liveFlows, setLiveFlows] = useState([])
  const [trafficLoading, setTrafficLoading] = useState(true)
  const [trafficError, setTrafficError] = useState(null)

  const [trafficHistory, setTrafficHistory] = useState([])
  const [historyLoading, setHistoryLoading] = useState(true)
  const [historyError, setHistoryError] = useState(null)

  const [topologyData, setTopologyData] = useState(EMPTY_TOPOLOGY)
  const [topologyLoading, setTopologyLoading] = useState(true)
  const [topologyRefreshing, setTopologyRefreshing] = useState(false)
  const [topologyError, setTopologyError] = useState(null)
  const [topologyLastUpdated, setTopologyLastUpdated] = useState(null)
  const [topologyRefreshMs, setTopologyRefreshMs] = useState(DEFAULT_TOPOLOGY_REFRESH_MS)

  const [monitorStatus, setMonitorStatus] = useState('idle')
  const [monitorMessage, setMonitorMessage] = useState(null)
  const [monitorActionLoading, setMonitorActionLoading] = useState(false)
  const [monitorError, setMonitorError] = useState(null)

  const scanPollRef = useRef(null)
  const monitorPollRef = useRef(null)
  const scanRuntimeVersionRef = useRef(0)
  const monitorRuntimeVersionRef = useRef(0)

  const monitoringActive = ['pending', 'running', 'stopping'].includes(monitorStatus)

  const fetchDevices = async () => {
    try {
      const response = await axios.get(`${API_BASE_URL}${API_ENDPOINTS.devices}`, { timeout: 5000 })
      setDevices(Array.isArray(response.data) ? response.data : [])
      setDevicesError(null)
    } catch (err) {
      setDevicesError(describeRequestFailure(err, 'Cihaz envanteri yüklenemedi.'))
    } finally {
      setDevicesLoading(false)
    }
  }

  const fetchMetrics = async () => {
    try {
      const response = await axios.get(`${API_BASE_URL}${API_ENDPOINTS.metrics}`, { timeout: 5000 })
      setSystemMetrics(response.data)
      setMetricsError(null)
    } catch (err) {
      setMetricsError(describeRequestFailure(err, 'Sistem metrikleri yüklenemedi.'))
    } finally {
      setMetricsLoading(false)
    }
  }

  const fetchTraffic = async () => {
    try {
      const [packetResponse, flowResponse] = await Promise.all([
        axios.get(`${API_BASE_URL}${API_ENDPOINTS.monitorPackets}`, { timeout: 5000 }),
        axios.get(`${API_BASE_URL}${API_ENDPOINTS.monitorFlows}`, { timeout: 5000 })
      ])
      setLivePackets(Array.isArray(packetResponse.data) ? packetResponse.data : [])
      setLiveFlows(Array.isArray(flowResponse.data) ? flowResponse.data : [])
      setTrafficError(null)
    } catch (err) {
      setLivePackets([])
      setLiveFlows([])
      setTrafficError(describeRequestFailure(err, 'Canlı trafik verisi yüklenemedi.'))
    } finally {
      setTrafficLoading(false)
    }
  }

  const fetchTrafficHistory = async () => {
    try {
      const response = await axios.get(`${API_BASE_URL}${API_ENDPOINTS.monitorHistory}`, { timeout: 5000 })
      setTrafficHistory(Array.isArray(response.data) ? response.data : [])
      setHistoryError(null)
    } catch (err) {
      setTrafficHistory([])
      setHistoryError(describeRequestFailure(err, 'Trafik geçmişi yüklenemedi.'))
    } finally {
      setHistoryLoading(false)
    }
  }

  const fetchTopology = async ({ showLoading = false } = {}) => {
    if (showLoading) {
      setTopologyRefreshing(true)
    }

    try {
      const response = await axios.get(`${API_BASE_URL}${API_ENDPOINTS.monitorTopology}`, { timeout: 5000 })
      setTopologyData(response.data || EMPTY_TOPOLOGY)
      setTopologyError(null)
      setTopologyLastUpdated(new Date())
    } catch (err) {
      setTopologyData(EMPTY_TOPOLOGY)
      setTopologyError(describeRequestFailure(err, 'Topoloji verisi yüklenemedi.'))
    } finally {
      setTopologyLoading(false)
      setTopologyRefreshing(false)
    }
  }

  const stopStatusPolling = () => {
    if (scanPollRef.current) {
      clearInterval(scanPollRef.current)
      scanPollRef.current = null
    }
  }

  const stopMonitorPolling = () => {
    if (monitorPollRef.current) {
      clearInterval(monitorPollRef.current)
      monitorPollRef.current = null
    }
  }

  const applyScanRuntimeState = (runtime) => {
    const status = runtime?.status || 'idle'
    const failedDevices = Number(runtime?.summary?.failed_devices || 0)

    setScanLoading(Boolean(runtime?.is_running))
    setScanProgress((current) => (runtime?.is_running ? Math.max(5, current > 99 ? 5 : current) : status === 'completed' ? 100 : 0))

    if (status === 'failed') {
      setScanError(runtime?.error || runtime?.message || 'Tarama başarısız oldu.')
      setScanNotice(null)
      return
    }

    setScanError(null)

    if (status === 'completed') {
      setScanNotice(
        runtime?.message ||
        (failedDevices > 0
          ? `Tarama ${failedDevices} cihaz düzeyinde hatayla tamamlandı.`
          : 'Tarama başarıyla tamamlandı.')
      )
      return
    }

    if (status === 'pending' || status === 'running') {
      setScanNotice(runtime?.message || null)
      return
    }

    setScanNotice(null)
  }

  const applyMonitorRuntimeState = (runtime) => {
    const status = runtime?.status || 'idle'
    setMonitorStatus(status)
    setMonitorMessage(runtime?.message || null)
      setMonitorError(status === 'failed' ? runtime?.error || runtime?.message || 'Canlı izleme başarısız oldu.' : null)
  }

  const fetchScanRuntimeState = async ({ forceApply = false } = {}) => {
    const requestVersion = scanRuntimeVersionRef.current
    try {
      const response = await axios.get(`${API_BASE_URL}${API_ENDPOINTS.scanStatus}`, { timeout: 5000 })
      if (forceApply || requestVersion === scanRuntimeVersionRef.current) {
        applyScanRuntimeState(response.data)
      }
      return response.data
    } catch (err) {
      setScanError((current) => current || describeRequestFailure(err, 'Tarama durumu backend üzerinden yüklenemedi.'))
      return null
    }
  }

  const fetchMonitorRuntimeState = async ({ forceApply = false } = {}) => {
    const requestVersion = monitorRuntimeVersionRef.current
    try {
      const response = await axios.get(`${API_BASE_URL}${API_ENDPOINTS.monitorLiveStatus}`, { timeout: 5000 })
      if (forceApply || requestVersion === monitorRuntimeVersionRef.current) {
        applyMonitorRuntimeState(response.data)
      }
      return response.data
    } catch (err) {
      setMonitorError((current) => current || describeRequestFailure(err, 'Canlı izleme durumu backend üzerinden yüklenemedi.'))
      return null
    }
  }

  const handleScanCompletion = async (job) => {
    const failedDevices = Array.isArray(job?.result?.failed_devices) ? job.result.failed_devices : []
    setScanLoading(false)
    setScanProgress(100)
    setScanError(null)
    setScanNotice(
      failedDevices.length > 0
        ? `Tarama ${failedDevices.length} cihaz düzeyinde hatayla tamamlandı.`
        : 'Tarama başarıyla tamamlandı.'
    )

    clearAllDeviceAnalysis()
    await fetchDevices()
    if (activeTab === 'topology') {
      await fetchTopology()
    }

    window.setTimeout(() => setScanProgress(0), 3000)
  }

  const pollScanJob = (jobId, immediate = false) => {
    if (!jobId) {
      return
    }

    stopStatusPolling()

    const checkStatus = async () => {
      try {
        const response = await axios.get(`${API_BASE_URL}${API_ENDPOINTS.scanJobs}/${jobId}`, { timeout: 3000 })
        const { status, progress } = response.data

        setScanLoading(status === 'pending' || status === 'running')
        setScanProgress(progress || 0)

        if (status === 'completed') {
          stopStatusPolling()
          await handleScanCompletion(response.data)
        } else if (status === 'failed') {
          stopStatusPolling()
          setScanLoading(false)
          setScanProgress(0)
          setScanError(`Ayrıntılı tarama hatası: ${formatJobFailure(response.data)}`)
        }
      } catch (err) {
        stopStatusPolling()
        setScanError(describeRequestFailure(err, 'Tarama durum güncellemeleri kesildi. Backend\'in hâlâ çalıştığını kontrol edin.'))
        await fetchScanRuntimeState()
      }
    }

    if (immediate) {
      checkStatus()
    }

    scanPollRef.current = setInterval(checkStatus, SCAN_STATUS_REFRESH_MS)
  }

  const startScan = async ({ targetRange = '', profile = 'vulnerability' } = {}) => {
    stopStatusPolling()
    scanRuntimeVersionRef.current += 1
    setScanLoading(true)
    setScanProgress(5)
    setScanError(null)
    setScanNotice(null)

    try {
      const params = { profile }
      const normalizedTarget = targetRange.trim()
      if (normalizedTarget) {
        params.target_range = normalizedTarget
      }

      const response = await axios.post(`${API_BASE_URL}${API_ENDPOINTS.scans}`, null, { params, timeout: 8000 })
      const jobId = response.data.job_id

      if (!jobId) {
        throw new Error('Tarama yanıtında job ID eksik')
      }

      if (response.data.status === 'running') {
        setScanNotice(response.data.message || 'Bir tarama zaten çalışıyor.')
      }

      pollScanJob(jobId, true)
    } catch (err) {
      setScanError(describeRequestFailure(err, 'Tarama başlatılamadı.'))
      setScanLoading(false)
      setScanProgress(0)
    }
  }

  const toggleMonitoring = async () => {
    try {
      monitorRuntimeVersionRef.current += 1
      setMonitorActionLoading(true)
      setMonitorError(null)

      if (!monitoringActive) {
        const response = await axios.post(`${API_BASE_URL}${API_ENDPOINTS.monitorLiveStart}`, null, { params: { duration: LIVE_CAPTURE_WINDOW_SECONDS }, timeout: 8000 })

        const runtime = await fetchMonitorRuntimeState({ forceApply: true })
        if (runtime?.is_running) {
          setTrafficLoading(true)
          setHistoryLoading(true)
          fetchTraffic()
          fetchTrafficHistory()
        } else if (!runtime) {
          setMonitorError(response.data.message || 'Canlı izleme başlatılamadı.')
        }
      } else {
        const response = await axios.post(`${API_BASE_URL}${API_ENDPOINTS.monitorLiveStop}`, null, { timeout: 5000 })
        const runtime = await fetchMonitorRuntimeState({ forceApply: true })

        if (!runtime && response.data.status !== 'stopping' && response.data.status !== 'idle') {
          setMonitorError(response.data.message || 'Canlı izleme durdurma isteği doğrulanmadı.')
        }
      }
    } catch (err) {
      setMonitorError(describeRequestFailure(err, 'Canlı izleme işlemi başarısız oldu.'))
    } finally {
      setMonitorActionLoading(false)
    }
  }

  useEffect(() => {
    fetchDevices()
    fetchScanRuntimeState().then((runtime) => {
      if (runtime?.is_running && runtime?.active_job_id) {
        pollScanJob(runtime.active_job_id, true)
      }
    })
    fetchMonitorRuntimeState()

    const interval = setInterval(fetchDevices, DEVICE_REFRESH_MS)
    return () => clearInterval(interval)
    // Initial bootstrap only; polling callbacks intentionally read current state through refs/service calls.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  useEffect(() => {
    if (!['pending', 'running', 'stopping'].includes(monitorStatus)) {
      stopMonitorPolling()
      return undefined
    }

    fetchMonitorRuntimeState()
    monitorPollRef.current = setInterval(fetchMonitorRuntimeState, MONITOR_STATUS_REFRESH_MS)
    return () => stopMonitorPolling()
    // Monitor polling is keyed only by runtime state transitions.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [monitorStatus])

  useEffect(() => {
    if (activeTab !== 'metrics' && activeTab !== 'anomalies') {
      return undefined
    }

    fetchMetrics()
    const interval = setInterval(fetchMetrics, METRICS_REFRESH_MS)
    return () => clearInterval(interval)
  }, [activeTab])

  useEffect(() => {
    if (!['packets', 'flows', 'anomalies'].includes(activeTab)) {
      return undefined
    }

    fetchTraffic()
    const interval = setInterval(fetchTraffic, TRAFFIC_REFRESH_MS)
    return () => clearInterval(interval)
  }, [activeTab])

  useEffect(() => {
    if (activeTab !== 'anomalies') {
      return undefined
    }

    fetchTrafficHistory()
    const interval = setInterval(fetchTrafficHistory, HISTORY_REFRESH_MS)
    return () => clearInterval(interval)
  }, [activeTab])

  useEffect(() => {
    if (activeTab !== 'topology') {
      return undefined
    }

    fetchTopology()
    const interval = topologyRefreshMs > 0 ? setInterval(() => fetchTopology(), topologyRefreshMs) : null
    return () => {
      if (interval) {
        clearInterval(interval)
      }
    }
  }, [activeTab, topologyRefreshMs])

  useEffect(() => {
    if (!selectedDevice) {
      if (assistantOpen) {
        setAssistantOpen(false)
      }
      return
    }

    const refreshedDevice = devices.find((device) => device.ip === selectedDevice.ip)
    if (refreshedDevice) {
      setSelectedDevice(refreshedDevice)
    } else if (!devicesLoading) {
      setSelectedDevice(null)
    }
  }, [assistantOpen, devices, devicesLoading, selectedDevice])

  const clearSelectedDevice = () => {
    setSelectedDevice(null)
    setAssistantOpen(false)
  }

  useEffect(() => () => {
    stopStatusPolling()
    stopMonitorPolling()
  }, [])

  const openTab = (tab) => {
    setActiveTab(tab)
    clearSelectedDevice()
  }

  const headerError = scanError || devicesError
  const scanState = scanLoading ? 'running' : scanError ? 'failed' : scanNotice?.includes('hata') ? 'partial' : scanNotice ? 'completed' : 'idle'

  const scanStateMeta = {
    idle: {
      label: 'Hazır',
      className: 'status-pill status-pill-neutral',
      icon: <Clock3 size={12} />,
      copy: 'Envanter, risk ve topoloji verilerini yenilemek için bir ağ taraması başlatın.'
    },
    running: {
      label: 'Çalışıyor',
      className: 'status-pill status-pill-running',
      icon: <Loader2 size={12} className="spin" />,
      copy: scanNotice || 'Yerel ağ taranıyor. Sonuçlar geldikçe envanter ve topoloji güncellenir.'
    },
    completed: {
      label: 'Tamamlandı',
      className: 'status-pill status-pill-success',
      icon: <CheckCircle2 size={12} />,
      copy: scanNotice || 'Son tarama başarıyla tamamlandı.'
    },
    partial: {
      label: 'Sorunlarla Tamamlandı',
      className: 'status-pill status-pill-warning',
      icon: <AlertTriangle size={12} />,
      copy: scanNotice || 'Son tarama kısmi hatalarla tamamlandı.'
    },
    failed: {
      label: 'Başarısız',
      className: 'status-pill status-pill-danger',
      icon: <AlertTriangle size={12} />,
      copy: scanError || 'Son tarama başarısız oldu.'
    }
  }

  const renderMetricsView = () => (
    <div className="fade-in">
      <div className="flex-row gap-6" style={{ display: 'grid', gridTemplateColumns: '1fr 1fr' }}>
        <div className="card flex-col p-0" style={{ padding: '24px' }}>
          <h3 className="flex-row items-center gap-2 mb-4" style={{ margin: 0 }}>
            <Zap size={18} color="var(--warning)" /> Model Doğrulama
          </h3>
          {metricsLoading ? (
            <div className="empty-state p-0" style={{ minHeight: '160px' }}>
              <div className="skeleton skeleton-icon" style={{ width: '40px', height: '40px', marginBottom: '16px', borderRadius: '50%' }}></div>
              <div className="skeleton skeleton-text" style={{ width: '120px' }}></div>
            </div>
          ) : metricsError ? (
            <div className="empty-state p-0" style={{ minHeight: '160px' }}>
              <AlertTriangle className="empty-state-icon" style={{ color: 'var(--danger)', width: '36px', height: '36px' }} />
              <div className="empty-state-copy" style={{ color: 'var(--danger)' }}>{metricsError}</div>
            </div>
          ) : systemMetrics ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span>F1 Skoru</span>
                <span style={{ fontWeight: 600 }}>{((systemMetrics.synthetic_training_metrics?.f1_score || 0) * 100).toFixed(1)}%</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span>Kesinlik</span>
                <span style={{ fontWeight: 600 }}>{((systemMetrics.synthetic_training_metrics?.precision || 0) * 100).toFixed(1)}%</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span>Duyarlılık</span>
                <span style={{ fontWeight: 600 }}>{((systemMetrics.synthetic_training_metrics?.recall || 0) * 100).toFixed(1)}%</span>
              </div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '8px' }}>
                <Info size={12} /> Bu değerler mevcut anomali modelinin doğrulama metriklerini özetler.
              </div>
            </div>
          ) : (
            <div className="empty-state p-0" style={{ minHeight: '160px' }}>
              <BarChart3 className="empty-state-icon" style={{ width: '36px', height: '36px' }} />
              <div className="empty-state-copy">Henüz doğrulama metriği bulunmuyor.</div>
            </div>
          )}
        </div>

        <div className="card flex-col p-0" style={{ padding: '24px' }}>
          <h3 className="flex-row items-center gap-2 mb-4" style={{ margin: 0 }}>
            <Shield size={18} color="var(--success)" /> Operasyon Özeti
          </h3>
          {metricsLoading ? (
            <div className="empty-state p-0" style={{ minHeight: '160px' }}>
              <div className="skeleton skeleton-icon" style={{ width: '40px', height: '40px', marginBottom: '16px', borderRadius: '50%' }}></div>
              <div className="skeleton skeleton-text" style={{ width: '120px' }}></div>
            </div>
          ) : metricsError ? (
            <div className="empty-state p-0" style={{ minHeight: '160px' }}>
              <AlertTriangle className="empty-state-icon" style={{ color: 'var(--danger)', width: '36px', height: '36px' }} />
              <div className="empty-state-copy" style={{ color: 'var(--danger)' }}>{metricsError}</div>
            </div>
          ) : systemMetrics ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span>Tespit Edilen Anomaliler (24s)</span>
                <span style={{ fontWeight: 600, color: 'var(--danger)' }}>{systemMetrics.real_world_metrics?.anomalies_detected_24h || 0}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span>Yanlış Pozitif Oranı</span>
                <span style={{ fontWeight: 600 }}>{formatFalsePositiveRate(systemMetrics.real_world_metrics)}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span>Raporlanan Çalışma Süresi</span>
                <span style={{ fontWeight: 600 }}>{systemMetrics.real_world_metrics?.system_uptime || 'Yok'}</span>
              </div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '8px' }}>
                <Info size={12} /> Canlı izleme değerleri şu anda en güncel backend özetini yansıtır.
              </div>
            </div>
          ) : (
            <div className="empty-state p-0" style={{ minHeight: '160px' }}>
              <BarChart3 className="empty-state-icon" style={{ width: '36px', height: '36px' }} />
              <div className="empty-state-copy">Henüz operasyon özeti bulunmuyor.</div>
            </div>
          )}
        </div>
      </div>

      <div className="card" style={{ marginTop: '24px', padding: '24px' }}>
        <div className="section-header" style={{ marginBottom: '18px' }}>
          <div>
            <h3 className="flex-row items-center gap-2" style={{ margin: 0 }}>
              <CheckCircle2 size={18} color="var(--success)" /> Akademik Dogrulama Kanitlari
            </h3>
            <div className="section-subtitle" style={{ marginTop: '6px' }}>
              N-BaIoT benchmark, overfitting riski, genelleme testleri ve leakage analizi final sunumu icin tek yerde ozetlenir.
            </div>
          </div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, minmax(0, 1fr))', gap: '14px' }}>
          {[
            ['N-BaIoT kayit', NBAIOT_KEY_FINDINGS.sampleCount, 'Processed benchmark satiri'],
            ['Feature sayisi', NBAIOT_KEY_FINDINGS.featureCount, 'N-BaIoT numeric feature semasi'],
            ['Normal / Anomaly', `${NBAIOT_KEY_FINDINGS.normalCount} / ${NBAIOT_KEY_FINDINGS.anomalyCount}`, 'Binary benchmark dagilimi'],
            ['Random split F1', `${(NBAIOT_KEY_FINDINGS.randomForestF1 * 100).toFixed(4)}%`, 'Random Forest en yuksek benchmark'],
            ['Balanced RF F1', `${(NBAIOT_KEY_FINDINGS.balancedRfF1 * 100).toFixed(4)}%`, 'Dengeli normal/anomaly random split'],
            ['Device split F1', `${(NBAIOT_KEY_FINDINGS.deviceSplitF1 * 100).toFixed(4)}%`, 'Cihaz bazli genelleme testi'],
            ['Attack split F1', `${(NBAIOT_KEY_FINDINGS.attackSplitF1 * 100).toFixed(2)}%`, 'Gorulmeyen saldiri ailesi testi'],
            ['Device+Attack F1', `${(NBAIOT_KEY_FINDINGS.deviceAttackSplitF1 * 100).toFixed(2)}%`, 'Gorulmeyen cihaz + saldiri ailesi'],
            ['Leakage suspect', NBAIOT_KEY_FINDINGS.leakageFeature, `Tek feature F1 ${(NBAIOT_KEY_FINDINGS.leakageFeatureF1 * 100).toFixed(2)}%`],
            ['IF best contamination', NBAIOT_KEY_FINDINGS.bestIsolationContamination, `F1 ${(NBAIOT_KEY_FINDINGS.bestIsolationF1 * 100).toFixed(2)}%`],
          ].map(([label, value, source]) => (
            <div key={label} className="soft-panel" style={{ padding: '16px' }}>
              <div className="metric-label">{label}</div>
              <div style={{ marginTop: '8px', fontWeight: 800, fontSize: '1.05rem' }}>{value}</div>
              <div className="table-secondary" style={{ marginTop: '4px' }}>{source}</div>
            </div>
          ))}
        </div>

        <div className="soft-panel" style={{ marginTop: '16px', padding: '18px', borderColor: 'rgba(45, 212, 191, 0.22)' }}>
          <div className="metric-label">Akademik yorum</div>
          <div style={{ marginTop: '8px', color: 'var(--text-secondary)', lineHeight: 1.55 }}>
            Random split ve balanced random split model kapasitesini gosterir, fakat genelleme guvenilirligini tek basina kanitlamaz.
            Attack-family ve device+attack split sonuclari F1 degerini yaklasik 0.80 seviyesine indirerek ezberleme riskini olculebilir
            hale getirdi. N-BaIoT modeli canli Sentinel-IoT akisina dogrudan baglanan bir production modeli degildir; offline benchmark
            kaniti olarak konumlandirilmalidir.
          </div>
        </div>

        <div style={{ marginTop: '20px', overflowX: 'auto' }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>Model</th>
                <th>Accuracy</th>
                <th>Precision</th>
                <th>Recall</th>
                <th>F1-score</th>
                <th>FPR</th>
                <th>FNR</th>
              </tr>
            </thead>
            <tbody>
              {NBAIOT_BENCHMARK_ROWS.map((row) => (
                <tr key={row.model}>
                  <td><span className="table-primary">{row.model}</span></td>
                  <td>{(row.accuracy * 100).toFixed(4)}%</td>
                  <td>{(row.precision * 100).toFixed(4)}%</td>
                  <td>{(row.recall * 100).toFixed(4)}%</td>
                  <td><strong>{(row.f1 * 100).toFixed(4)}%</strong></td>
                  <td>{(row.fpr * 100).toFixed(4)}%</td>
                  <td>{(row.fnr * 100).toFixed(4)}%</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '18px', marginTop: '20px' }}>
          <div className="soft-panel" style={{ padding: '16px' }}>
            <div className="metric-label">Generalization comparison</div>
            <img
              src="/evaluation/nbaiot_generalization_comparison.png"
              alt="N-BaIoT generalization comparison F1-score chart"
              style={{ width: '100%', marginTop: '12px', borderRadius: '8px', background: '#fff' }}
            />
            <div className="table-secondary" style={{ marginTop: '8px' }}>
              Kaynak: evaluation/results/nbaiot_generalization_comparison.png
            </div>
          </div>

          <div className="soft-panel" style={{ padding: '16px' }}>
            <div className="metric-label">Top feature importance</div>
            <img
              src="/evaluation/nbaiot_top_feature_importance.png"
              alt="N-BaIoT top feature importance chart"
              style={{ width: '100%', marginTop: '12px', borderRadius: '8px', background: '#fff' }}
            />
            <div className="table-secondary" style={{ marginTop: '8px' }}>
              Kaynak: evaluation/results/nbaiot_top_feature_importance.png
            </div>
          </div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '18px', marginTop: '20px' }}>
          <div className="soft-panel" style={{ padding: '16px' }}>
            <div className="metric-label">Device + Attack split matrix</div>
            <img
              src="/evaluation/nbaiot_device_attack_split_confusion_matrix.png"
              alt="N-BaIoT Device plus Attack split confusion matrix"
              style={{ width: '100%', marginTop: '12px', borderRadius: '8px', background: '#fff' }}
            />
            <div className="table-secondary" style={{ marginTop: '8px' }}>
              Kaynak: evaluation/results/nbaiot_device_attack_split_confusion_matrix.png
            </div>
          </div>

          <div className="soft-panel" style={{ padding: '16px' }}>
            <div className="metric-label">Worst attack-family split matrix</div>
            <img
              src="/evaluation/nbaiot_attack_split_confusion_matrix_gafgyt.png"
              alt="N-BaIoT held-out gafgyt attack split confusion matrix"
              style={{ width: '100%', marginTop: '12px', borderRadius: '8px', background: '#fff' }}
            />
            <div className="table-secondary" style={{ marginTop: '8px' }}>
              Kaynak: evaluation/results/nbaiot_attack_split_confusion_matrix_gafgyt.png
            </div>
          </div>
        </div>

        <div className="soft-panel" style={{ marginTop: '18px', padding: '16px' }}>
          <div className="metric-label">Sunumda one cikarilacak sonuc</div>
          <div style={{ marginTop: '8px', color: 'var(--text-secondary)', lineHeight: 1.55 }}>
            Sunumda random split basarisini tek basina savunmak yerine genelleme sinirini acikca gosterin: Device Split RF F1-score
            {(NBAIOT_KEY_FINDINGS.deviceSplitF1 * 100).toFixed(4)}%, fakat Attack Split RF F1-score {(NBAIOT_KEY_FINDINGS.attackSplitF1 * 100).toFixed(2)}%
            ve Device+Attack Split RF F1-score {(NBAIOT_KEY_FINDINGS.deviceAttackSplitF1 * 100).toFixed(2)}%. Bu tablo modelin kapasitesini ve
            ezberleme riskini birlikte raporlayan daha guvenilir akademik kanittir.
          </div>
        </div>
      </div>
    </div>
  )

  const renderContent = () => {
    if (selectedDevice) {
      return (
        <DeviceDetailView
          device={selectedDevice}
          onBack={clearSelectedDevice}
          onOpenAssistant={() => setAssistantOpen(true)}
          apiBaseUrl={API_BASE_URL}
        />
      )
    }

    switch (activeTab) {
      case 'inventory':
        return <InventoryView devices={devices} onSelectDevice={setSelectedDevice} loading={devicesLoading} error={devicesError} />
      case 'vulnerabilities':
        return <VulnerabilityView devices={devices} />
      case 'anomalies':
        return (
          <AnomalyView
            devices={devices}
            metrics={systemMetrics}
            metricsLoading={metricsLoading}
            metricsError={metricsError}
            livePackets={livePackets}
            trafficLoading={trafficLoading}
            trafficError={trafficError}
            trafficHistory={trafficHistory}
            historyLoading={historyLoading}
            historyError={historyError}
            monitoringActive={monitoringActive}
            monitorStatus={monitorStatus}
            monitorMessage={monitorMessage}
            monitorActionLoading={monitorActionLoading}
            monitorError={monitorError}
            onToggleMonitoring={toggleMonitoring}
          />
        )
      case 'packets':
        return <PacketListView packets={livePackets} loading={trafficLoading} error={trafficError} />
      case 'flows':
        return <FlowSummaryView flows={liveFlows} loading={trafficLoading} error={trafficError} />
      case 'topology':
        return (
          <TopologyView
            data={topologyData}
            loading={topologyLoading}
            refreshing={topologyRefreshing}
            error={topologyError}
            lastUpdated={topologyLastUpdated}
            refreshMs={topologyRefreshMs}
            onRefreshMsChange={setTopologyRefreshMs}
            onRefresh={() => fetchTopology({ showLoading: true })}
            onStartScan={startScan}
            scanLoading={scanLoading}
            monitoringActive={monitoringActive}
            onSelectDevice={(ip) => {
              const device = devices.find((entry) => entry.ip === ip)
              if (device) {
                setSelectedDevice(device)
              }
            }}
          />
        )
      case 'metrics':
        return renderMetricsView()
      default:
        return null
    }
  }

  return (
    <div className="app-container">
      <aside className="sidebar">
        <div className="sidebar-brand">
          <div className="sidebar-brand-mark">
            <Shield size={24} color="white" />
          </div>
          <div>
            <h2 className="sidebar-brand-title">Sentinel<span style={{ color: 'var(--accent-primary)' }}>IoT</span></h2>
            <div className="sidebar-brand-copy">Yerel ağ görünürlüğü ve izleme</div>
          </div>
        </div>

        <div className="sidebar-status-card">
          <div className="status-row">
            <div className="status-label">Son Tarama</div>
            <div className={scanStateMeta[scanState].className}>
              {scanStateMeta[scanState].icon}
              {scanStateMeta[scanState].label}
            </div>
          </div>
          <div className="status-copy">{scanStateMeta[scanState].copy}</div>
          {scanLoading && (
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.75rem', marginBottom: '6px', color: 'var(--text-secondary)' }}>
                <span>Tarama ilerlemesi</span>
                <span>{scanProgress}%</span>
              </div>
              <div style={{ height: '4px', background: 'rgba(255,255,255,0.1)', borderRadius: '2px' }}>
                <div style={{ width: `${scanProgress}%`, height: '100%', background: 'var(--accent-primary)', borderRadius: '2px', transition: 'width 0.3s' }}></div>
              </div>
            </div>
          )}
          <button className="btn btn-primary" style={{ width: '100%', justifyContent: 'center' }} onClick={startScan} disabled={scanLoading}>
            {scanLoading ? <Loader2 size={16} className="spin" /> : <Zap size={16} />}
            {scanLoading ? 'Taranıyor...' : 'Ağ Taramasını Başlat'}
          </button>
        </div>

        <nav style={{ marginTop: 'auto' }}>
          <div className="sidebar-nav-group">
            <div className="sidebar-section-label">Operasyonlar</div>
            <div className={`nav-item ${activeTab === 'inventory' ? 'active' : ''}`} onClick={() => openTab('inventory')}>
              <LayoutDashboard size={20} /> Envanter
            </div>
            <div className={`nav-item ${activeTab === 'vulnerabilities' ? 'active' : ''}`} onClick={() => openTab('vulnerabilities')}>
              <AlertTriangle size={20} /> Servis Görünürlüğü
            </div>
            <div className={`nav-item ${activeTab === 'metrics' ? 'active' : ''}`} onClick={() => openTab('metrics')}>
              <BarChart3 size={20} /> Doğrulama ve Özet
            </div>
          </div>

          <div className="sidebar-nav-group">
            <div className="sidebar-section-label">Canlı Analiz</div>
            <div className={`nav-item ${activeTab === 'anomalies' ? 'active' : ''}`} onClick={() => openTab('anomalies')}>
              <Activity size={20} /> İzleme
            </div>
            <div className={`nav-item ${activeTab === 'packets' ? 'active' : ''}`} onClick={() => openTab('packets')}>
              <List size={20} /> Paket Akışı
            </div>
            <div className={`nav-item ${activeTab === 'flows' ? 'active' : ''}`} onClick={() => openTab('flows')}>
              <Waves size={20} /> Canlı Akışlar
            </div>
            <div className={`nav-item ${activeTab === 'topology' ? 'active' : ''}`} onClick={() => openTab('topology')}>
              <Share2 size={20} /> Topoloji
            </div>
          </div>
        </nav>
      </aside>

      <main className="main-content">
        <header className="page-header">
          <div>
            <h1 className="page-title">
              {selectedDevice ? `Cihaz Detayları: ${selectedDevice.ip}` : (
                <>
                  {activeTab === 'inventory' && 'Cihaz Envanteri'}
                  {activeTab === 'vulnerabilities' && 'Servis Görünürlüğü'}
                  {activeTab === 'anomalies' && 'İzleme Görünümü'}
                  {activeTab === 'packets' && 'Paket Akışı'}
                  {activeTab === 'flows' && 'Canlı Akışlar'}
                  {activeTab === 'topology' && 'Ağ Topolojisi'}
                  {activeTab === 'metrics' && 'Doğrulama ve Özet'}
                </>
              )}
              {headerError && (
                <span className="error-badge">
                  <AlertTriangle size={14} /> {headerError}
                </span>
              )}
            </h1>
            <p className="page-copy">
              {selectedDevice
                ? 'Bu cihaz için risk geçmişini, izleme olaylarını, açık servisleri ve cihaza özel YZ yönlendirmesini inceleyin.'
                : 'Cihaz envanterini, izleme etkinliğini, servis görünürlüğünü ve cihaza özel güvenlik yönlendirmesini tek yerden izleyin.'}
            </p>
          </div>

          <div style={{ display: 'flex', gap: '12px' }}>
            <button
              className="card summary-tile assistant-launch"
              onClick={() => setAssistantOpen(true)}
              type="button"
            >
              <Sparkles size={18} color="var(--accent-primary)" />
              <div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>Güvenlik Asistanı</div>
                <div style={{ fontWeight: '700' }}>{selectedDevice ? 'Hızlı cihaz görünümü' : 'Bir cihaz seçin'}</div>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)', marginTop: '2px' }}>
                  {selectedDevice ? selectedDevice.ip : 'Yalnızca cihaz bağlamında kullanılabilir'}
                </div>
              </div>
            </button>
            <div className="card summary-tile">
              <Database size={18} color="var(--accent-primary)" />
              <div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>İzlenen Cihazlar</div>
                <div style={{ fontWeight: '700' }}>{devices.length}</div>
              </div>
            </div>
          </div>
        </header>

        <section className="fade-in">
          {renderContent()}
        </section>
      </main>

      <SecurityAssistantPanel
        isOpen={assistantOpen}
        onClose={() => setAssistantOpen(false)}
        device={selectedDevice}
        apiBaseUrl={API_BASE_URL}
      />
    </div>
  )
}

export default App
