export const DEVICE_ANALYSIS_VIEWS = {
  risk_explanation: {
    label: 'Bu cihaz neden riskli',
    empty: 'Cihazın mevcut riskini sade bir dille görmek için bu eylemi seçin.',
  },
  anomaly_summary: {
    label: 'Son anomali bağlamı',
    empty: 'Seçili cihaz için son izleme anomalilerini özetlemek üzere bu eylemi seçin.',
  },
  next_actions: {
    label: 'Önerilen sonraki adımlar',
    empty: 'Seçili cihaz için öncelikli sonraki adımları görmek üzere bu eylemi seçin.',
  },
}

export const describeLlmUiFailure = (err, fallback) => {
  if (err.code === 'ECONNABORTED') {
    return 'İstek zaman aşımına uğradı. Backend veya model sağlayıcısı meşgul olabilir.'
  }

  if (!err.response) {
    return 'YZ servisine ulaşılamadı. API sunucusunun çalıştığını kontrol edin.'
  }

  if (typeof err.response.data.detail === 'string') {
    return err.response.data.detail
  }

  if (err.response.status >= 500) {
    return 'YZ servisi şu anda kullanılamıyor. Backend veya sağlayıcı yapılandırmasını kontrol edin.'
  }

  return fallback
}
