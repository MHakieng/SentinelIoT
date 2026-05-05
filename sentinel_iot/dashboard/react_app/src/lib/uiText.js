export const translateRiskStatus = (status) => {
  switch (status) {
    case 'Critical Risk':
      return 'Kritik Risk'
    case 'High Risk':
      return 'Yüksek Risk'
    case 'Medium Risk':
      return 'Orta Risk'
    case 'Safe':
      return 'Güvenli'
    case 'Unknown':
    default:
      return 'Bilinmiyor'
  }
}

export const translateEvidenceSource = (source) => {
  switch (source) {
    case 'device_inventory':
      return 'Cihaz envanteri'
    case 'risk_breakdown':
      return 'Risk dağılımı'
    case 'risk_history':
      return 'Risk geçmişi'
    case 'anomaly_logs':
      return 'Anomali kayıtları'
    case 'service_exposure':
      return 'Servis görünürlüğü'
    case 'service_fingerprint':
      return 'Servis parmak izi'
    case 'cve_score':
      return 'CVSS puanı'
    case 'cve_description':
      return 'Zafiyet açıklaması'
    case 'scan_reason':
      return 'Tarama gerekçesi'
    default:
      return source || 'Kaynak'
  }
}
