"""Merkezi feature şeması. Tüm modüller bu tanımı referans alır."""

FEATURE_SCHEMA = [
    'packet_count',
    'byte_count',
    'duration',
    'avg_packet_size',
    'mean_iat',
    'var_iat',
]


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
    known_extra = {'label', 'dst_ip', 'src_ip', 'protocols'}
    unexpected = extra - known_extra
    if unexpected:
        print(
            f"[{source}] FEATURE_SCHEMA uyarı: "
            f"Tanınmayan ek kolonlar: {unexpected}"
        )

    return True
