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
  List,
  Share2,
  CheckCircle2,
  Clock3,
  Sparkles
} from 'lucide-react'
import axios from 'axios'

import CommandCenterView from './components/command/CommandCenterView'
import InventoryView from './components/InventoryView'
import VulnerabilityView from './components/VulnerabilityView'
import AnomalyView from './components/AnomalyView'
import FlowSummaryView from './components/FlowSummaryView'
import DeviceDetailView from './components/DeviceDetailView'
import TopologyView from './components/TopologyView'
import SecurityAssistantPanel from './components/SecurityAssistantPanel'
import MetricsView from './components/MetricsView'
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
const SCAN_PROFILE_OPTIONS = [
  { value: 'quick', label: 'Hızlı', description: 'Hızlı genel tarama' },
  { value: 'iot_discovery', label: 'IoT Keşif', description: 'IoT odaklı portlar' },
  { value: 'vulnerability', label: 'Zafiyet', description: 'CVE ve servis odaklı tarama' },
  { value: 'full', label: 'Kapsamlı', description: 'Daha yavaş, kapsamlı tarama' },
]
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

  if (typeof err.response.data.detail === 'string') {
    return err.response.data.detail
  }

  return fallback
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
  const [activeTab, setActiveTab] = useState('command')
  const [devices, setDevices] = useState([])
  const [selectedDevice, setSelectedDevice] = useState(null)
  const [assistantOpen, setAssistantOpen] = useState(false)

  const [scanLoading, setScanLoading] = useState(false)
  const [scanProgress, setScanProgress] = useState(0)
  const [scanError, setScanError] = useState(null)
  const [scanNotice, setScanNotice] = useState(null)
  const [scanJobs, setScanJobs] = useState([])
  const [selectedScanProfile, setSelectedScanProfile] = useState('vulnerability')
  const [liveCaptureSeconds, setLiveCaptureSeconds] = useState(LIVE_CAPTURE_WINDOW_SECONDS)
  const [trafficRefreshMs, setTrafficRefreshMs] = useState(TRAFFIC_REFRESH_MS)

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
  const [monitorSummary, setMonitorSummary] = useState(null)
  const [monitorActionLoading, setMonitorActionLoading] = useState(false)
  const [monitorError, setMonitorError] = useState(null)

  const scanPollRef = useRef(null)
  const monitorPollRef = useRef(null)
  const scanRuntimeVersionRef = useRef(0)
  const monitorRuntimeVersionRef = useRef(0)

  const monitoringActive = ['pending', 'running', 'stopping'].includes(monitorStatus)

  const rememberScanJob = (job) => {
    if (!job?.id) return
    setScanJobs((current) => {
      const next = [job, ...current.filter((entry) => entry.id !== job.id)]
      return next.slice(0, 8)
    })
  }

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

  const fetchLatestScanJob = async () => {
    try {
      const response = await axios.get(`${API_BASE_URL}${API_ENDPOINTS.scanJobs}`, { timeout: 5000 })
      rememberScanJob(response.data)
    } catch {
      // Timeline can still render device and monitor-derived events without scanner job history.
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
    setMonitorSummary(runtime?.summary || null)
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
    if (activeTab === 'topology' || activeTab === 'command') {
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
        rememberScanJob(response.data)

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

  const startScan = async ({ targetRange = '', profile = selectedScanProfile } = {}) => {
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
      const startedAt = new Date().toISOString()

      if (!jobId) {
        throw new Error('Tarama yanıtında job ID eksik')
      }

      rememberScanJob({
        id: jobId,
        type: 'scan',
        status: response.data.status || 'pending',
        started_at: startedAt,
        updated_at: startedAt,
        progress: 0,
        target: normalizedTarget || null,
        message: response.data.message || null,
      })

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
        const response = await axios.post(`${API_BASE_URL}${API_ENDPOINTS.monitorLiveStart}`, null, { params: { duration: liveCaptureSeconds }, timeout: 8000 })
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
    fetchLatestScanJob()
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
    if (!['command', 'validation', 'live'].includes(activeTab)) {
      return undefined
    }

    fetchMetrics()
    const interval = setInterval(fetchMetrics, METRICS_REFRESH_MS)
    return () => clearInterval(interval)
  }, [activeTab])

  useEffect(() => {
    if (!['command', 'live', 'topology'].includes(activeTab)) {
      return undefined
    }

    fetchTraffic()
    const interval = setInterval(fetchTraffic, trafficRefreshMs)
    return () => clearInterval(interval)
  }, [activeTab, trafficRefreshMs])

  useEffect(() => {
    if (!['command', 'live'].includes(activeTab)) {
      return undefined
    }

    fetchTrafficHistory()
    const interval = setInterval(fetchTrafficHistory, HISTORY_REFRESH_MS)
    return () => clearInterval(interval)
  }, [activeTab])

  useEffect(() => {
    if (!['command', 'topology'].includes(activeTab)) {
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

  const renderCommandCenter = () => (
    <CommandCenterView
      devices={devices}
      devicesLoading={devicesLoading}
      devicesError={devicesError}
      topologyData={topologyData}
      topologyLoading={topologyLoading}
      topologyRefreshing={topologyRefreshing}
      topologyError={topologyError}
      topologyLastUpdated={topologyLastUpdated}
      trafficHistory={trafficHistory}
      historyLoading={historyLoading}
      historyError={historyError}
      liveFlows={liveFlows}
      livePackets={livePackets}
      trafficLoading={trafficLoading}
      trafficError={trafficError}
      systemMetrics={systemMetrics}
      metricsLoading={metricsLoading}
      metricsError={metricsError}
      scanJobs={scanJobs}
      scanState={scanState}
      scanStateMeta={scanStateMeta}
      scanLoading={scanLoading}
      scanProgress={scanProgress}
      scanError={scanError}
      monitorStatus={monitorStatus}
      monitoringActive={monitoringActive}
      monitorSummary={monitorSummary}
      monitorActionLoading={monitorActionLoading}
      monitorError={monitorError}
      selectedDevice={selectedDevice}
      selectedScanProfile={selectedScanProfile}
      scanProfileOptions={SCAN_PROFILE_OPTIONS}
      onScanProfileChange={setSelectedScanProfile}
      onSelectDevice={setSelectedDevice}
      onStartScan={startScan}
      onRefreshTopology={() => fetchTopology({ showLoading: true })}
      onToggleMonitoring={toggleMonitoring}
      apiBaseUrl={API_BASE_URL}
    />
  )

  const renderContent = () => {
    if (selectedDevice && activeTab !== 'command') {
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
      case 'command':
        return renderCommandCenter()
      case 'devices':
        return <InventoryView devices={devices} onSelectDevice={setSelectedDevice} loading={devicesLoading} error={devicesError} />
      case 'evidence':
        return <VulnerabilityView devices={devices} liveFlows={liveFlows} livePackets={livePackets} />
      case 'live':
        return (
          <div style={{ display: 'grid', gap: '24px' }}>
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
              monitorSummary={monitorSummary}
              monitorActionLoading={monitorActionLoading}
              monitorError={monitorError}
              onToggleMonitoring={toggleMonitoring}
            />
            <FlowSummaryView flows={liveFlows} loading={trafficLoading} error={trafficError} />
          </div>
        )
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
            devices={devices}
            onSelectDevice={(ip) => {
              const device = devices.find((entry) => entry.ip === ip)
              if (device) {
                setSelectedDevice(device)
              }
            }}
          />
        )
      case 'validation':
        return <MetricsView systemMetrics={systemMetrics} metricsLoading={metricsLoading} metricsError={metricsError} />
      case 'settings':
        return (
          <div className="card settings-panel">
            <div className="section-header">
              <div>
                <h3 style={{ margin: 0 }}>Ayarlar</h3>
              </div>
            </div>
            <div className="settings-grid">
              <div className="soft-panel device-summary-tile">
                <div className="metric-label">API Base URL</div>
                <div className="metric-value">{API_BASE_URL}</div>
              </div>
              <div className="soft-panel device-summary-tile">
                <div className="metric-label">Canlı yakalama penceresi</div>
                <div className="metric-value">{liveCaptureSeconds}s</div>
                <div className="settings-control-row">
                  {[10, 30, 60].map((value) => (
                    <button
                      key={value}
                      type="button"
                      className={`settings-chip ${liveCaptureSeconds === value ? 'active' : ''}`}
                      onClick={() => setLiveCaptureSeconds(value)}
                    >
                      {value}s
                    </button>
                  ))}
                </div>
              </div>
              <div className="soft-panel device-summary-tile">
                <div className="metric-label">Canlı doğrulama metriği</div>
                <div className="metric-value">{systemMetrics?.runtime_metrics_metadata?.source || 'Etiketli veri yok'}</div>
                <div className="status-note">Etiketli canlı pencere olmadan runtime accuracy/F1 hesaplanmaz.</div>
              </div>
              <div className="soft-panel device-summary-tile">
                <div className="metric-label">Varsayılan tarama profili</div>
                <div className="metric-value">{SCAN_PROFILE_OPTIONS.find((option) => option.value === selectedScanProfile)?.label || selectedScanProfile}</div>
                <select className="settings-select" value={selectedScanProfile} onChange={(event) => setSelectedScanProfile(event.target.value)}>
                  {SCAN_PROFILE_OPTIONS.map((option) => (
                    <option key={option.value} value={option.value}>{option.label} - {option.description}</option>
                  ))}
                </select>
              </div>
              <div className="soft-panel device-summary-tile">
                <div className="metric-label">Canlı veri yenileme</div>
                <div className="metric-value">{trafficRefreshMs / 1000}s</div>
                <div className="settings-control-row">
                  {[2000, 4000, 10000].map((value) => (
                    <button
                      key={value}
                      type="button"
                      className={`settings-chip ${trafficRefreshMs === value ? 'active' : ''}`}
                      onClick={() => setTrafficRefreshMs(value)}
                    >
                      {value / 1000}s
                    </button>
                  ))}
                </div>
              </div>
              <div className="soft-panel device-summary-tile">
                <div className="metric-label">Sınıf farkındalığı</div>
                <div className="metric-value">Aktif</div>
                <div className="status-note">Cihaz sınıfı, canlı akış skorlarının bağlama göre yorumlanmasına yardım eder.</div>
              </div>
              <div className="soft-panel device-summary-tile">
                <div className="metric-label">Paket yakalama notu</div>
                <div className="metric-value">Npcap / yetki</div>
                <div className="status-note">Canlı izleme için doğru ağ arayüzü ve yönetici yetkisi gerekebilir.</div>
              </div>
            </div>
          </div>
        )
      default:
        return renderCommandCenter()
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
            <div className="sidebar-section-label">Operasyon Merkezi</div>
            <div className={`nav-item ${activeTab === 'command' ? 'active' : ''}`} onClick={() => openTab('command')}>
              <LayoutDashboard size={20} /> Merkez
            </div>
            <div className={`nav-item ${activeTab === 'devices' ? 'active' : ''}`} onClick={() => openTab('devices')}>
              <Database size={20} /> Cihazlar
            </div>
            <div className={`nav-item ${activeTab === 'topology' ? 'active' : ''}`} onClick={() => openTab('topology')}>
              <Share2 size={20} /> Topoloji
            </div>
          </div>

          <div className="sidebar-nav-group">
            <div className="sidebar-section-label">Operasyonlar</div>
            <div className={`nav-item ${activeTab === 'live' ? 'active' : ''}`} onClick={() => openTab('live')}>
              <Activity size={20} /> Canlı İzleme
            </div>
            <div className={`nav-item ${activeTab === 'evidence' ? 'active' : ''}`} onClick={() => openTab('evidence')}>
              <AlertTriangle size={20} /> Kanıtlar
            </div>
            <div className={`nav-item ${activeTab === 'validation' ? 'active' : ''}`} onClick={() => openTab('validation')}>
              <BarChart3 size={20} /> Doğrulama
            </div>
            <div className={`nav-item ${activeTab === 'settings' ? 'active' : ''}`} onClick={() => openTab('settings')}>
              <List size={20} /> Ayarlar
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
                  {activeTab === 'command' && 'Operasyon Merkezi'}
                  {activeTab === 'devices' && 'Cihaz Envanteri'}
                  {activeTab === 'topology' && 'Ağ Topolojisi'}
                  {activeTab === 'live' && 'Canlı Operasyonlar'}
                  {activeTab === 'evidence' && 'Kanıtlar'}
                  {activeTab === 'validation' && 'Doğrulama'}
                  {activeTab === 'settings' && 'Ayarlar'}
                </>
              )}
              {headerError && (
                <span className="error-badge">
                  <AlertTriangle size={14} /> {headerError}
                </span>
              )}
            </h1>
          </div>

          <div style={{ display: 'flex', gap: '12px' }}>
            <button
              className="card summary-tile assistant-launch"
              onClick={() => setAssistantOpen(true)}
              type="button"
            >
              <Sparkles size={18} color="var(--accent-primary)" />
              <div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>AI Güvenlik Chatbotu</div>
                <div style={{ fontWeight: '700' }}>{selectedDevice ? 'Sohbeti aç' : 'Bir cihaz seçin'}</div>
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
