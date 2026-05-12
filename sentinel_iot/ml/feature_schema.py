"""Merkezi feature şeması. Tüm modüller bu tanımı referans alır."""

FEATURE_SCHEMA = [
    # ── Temel akış istatistikleri (6) ──
    'packet_count',
    'byte_count',
    'duration',
    'avg_packet_size',
    'mean_iat',
    'var_iat',
    # ── TCP protokol oranları (2) ──
    'tcp_syn_ratio',          # SYN paketleri / toplam TCP paketi
    'tcp_synack_ratio',       # SYN+ACK paketleri / toplam TCP paketi
    # ── Bağlantı istatistikleri (3) ──
    'unique_dst_ip_count',    # Aynı kaynak IP'den giden eşsiz hedef IP sayısı
    'unique_dst_port_count',  # Aynı kaynak IP'den giden eşsiz hedef port sayısı
    'rst_syn_ratio',          # RST / SYN oranı (başarısız bağlantı oranı)
    # ── DNS istatistikleri (2) ──
    'dns_query_response_ratio',  # DNS sorgu / cevap oranı
    'unique_domain_count',       # Eşsiz DNS domain sayısı
    # ── Zaman serisi / türetilmiş (4) ──
    'pkt_size_variance',      # Paket boyutu varyansı
    'bytes_per_second',       # Saniye başına byte (byte_count / duration)
    'small_pkt_ratio',        # Küçük paket oranı (< 128 byte)
    'large_pkt_ratio',        # Büyük paket oranı (> 1024 byte)
]

# Toplam: 17 feature


def validate_features(data, source="unknown"):
    """Veri setindeki feature alanlarını FEATURE_SCHEMA ile doğrula.
    
    Args:
        data: list[dict] — flow verisi
        source: str — hangi modülden çağrıldığını belirtir (log için)
    
    Returns:
        True — doğrulama başarılı
    
    Raises:
        ValueError — eksik feature varsa eğitimi durdurur
    """
    if not data:
        return True

    columns = set(data[0].keys())
    required = set(FEATURE_SCHEMA)

    # Eksik feature kontrolü → HATA, eğitimi durdur
    missing = required - columns
    if missing:
        raise ValueError(
            f"[{source}] FEATURE_SCHEMA doğrulama HATASI: "
            f"Eksik feature alanları: {missing}"
        )

    # Gereksiz kolon kontrolü → UYARI
    extra = columns - required
    # Bilinen ek kolonları filtrele (label, dst_ip, src_ip, protocols gibi)
    known_extra = {
        'label', 'dst_ip', 'src_ip', 'protocols',
        'flow_id', 'src_port', 'dst_port', 'protocol',
        'target', 'type', 'protocol_name',
        'anomaly_score', 'confidence',
    }
    unexpected = extra - known_extra
    if unexpected:
        print(
            f"[{source}] FEATURE_SCHEMA uyarı: "
            f"Tanınmayan ek kolonlar: {unexpected}"
        )

    return True
