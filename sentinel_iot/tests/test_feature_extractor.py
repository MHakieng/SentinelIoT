"""Unit tests for the flow-based feature extractor."""

from unittest.mock import MagicMock
from sentinel_iot.monitor.feature_extractor import extract_features
from sentinel_iot.ml.feature_schema import FEATURE_SCHEMA


def make_mock_packet(src, dst, proto, length, timestamp):
    """Create a mock Scapy packet with IP layer."""
    pkt = MagicMock()
    pkt.haslayer.return_value = True
    
    ip_layer = MagicMock()
    ip_layer.src = src
    ip_layer.dst = dst
    ip_layer.proto = proto
    pkt.__getitem__ = lambda self, cls: ip_layer
    pkt.__len__ = lambda self: length
    pkt.time = timestamp
    
    return pkt


class TestEmptyInput:
    def test_empty_list_returns_empty(self):
        assert extract_features(packets=[]) == []

    def test_none_packets_returns_empty(self):
        assert extract_features(packets=None) == []


class TestFeatureExtraction:
    def test_single_flow(self):
        packets = [
            make_mock_packet("192.168.1.1", "192.168.1.2", 6, 100, 1000.0),
            make_mock_packet("192.168.1.1", "192.168.1.2", 6, 150, 1001.0),
            make_mock_packet("192.168.1.1", "192.168.1.2", 6, 200, 1002.0),
        ]
        features = extract_features(packets=packets)
        
        assert len(features) == 1
        f = features[0]
        assert f["src_ip"] == "192.168.1.1"
        assert f["dst_ip"] == "192.168.1.2"
        assert f["packet_count"] == 3
        assert f["byte_count"] == 450
        assert f["duration"] == 2.0
        assert f["avg_packet_size"] == 150.0

    def test_multiple_flows(self):
        packets = [
            make_mock_packet("10.0.0.1", "10.0.0.2", 6, 100, 1000.0),
            make_mock_packet("10.0.0.3", "10.0.0.4", 17, 200, 1000.0),
        ]
        features = extract_features(packets=packets)
        assert len(features) == 2

    def test_iat_calculation(self):
        packets = [
            make_mock_packet("1.1.1.1", "2.2.2.2", 6, 100, 1000.0),
            make_mock_packet("1.1.1.1", "2.2.2.2", 6, 100, 1001.0),
            make_mock_packet("1.1.1.1", "2.2.2.2", 6, 100, 1003.0),
        ]
        features = extract_features(packets=packets)
        f = features[0]
        # IATs: [1.0, 2.0] → mean = 1.5
        assert f["mean_iat"] == 1.5
        # variance of [1.0, 2.0] = 0.5
        assert f["var_iat"] == 0.5

    def test_single_packet_flow(self):
        packets = [
            make_mock_packet("1.1.1.1", "2.2.2.2", 6, 64, 1000.0),
        ]
        features = extract_features(packets=packets)
        f = features[0]
        assert f["packet_count"] == 1
        assert f["mean_iat"] == 0.0
        assert f["var_iat"] == 0.0
        assert f["duration"] == 0.0


class TestExpandedFeatures:
    """Genişletilmiş 17-feature şemasının üretilip üretilmediğini doğrula."""

    def test_all_schema_features_present(self):
        """Çıktı dict'inde FEATURE_SCHEMA'daki tüm alanlar bulunmalı."""
        packets = [
            make_mock_packet("10.0.0.1", "10.0.0.2", 6, 100, 1000.0),
            make_mock_packet("10.0.0.1", "10.0.0.2", 6, 200, 1001.0),
        ]
        features = extract_features(packets=packets)
        f = features[0]
        for feature_name in FEATURE_SCHEMA:
            assert feature_name in f, f"Missing feature: {feature_name}"

    def test_zero_division_safety(self):
        """Tek paketlik flow'da sıfıra bölme olmamalı."""
        packets = [
            make_mock_packet("1.1.1.1", "2.2.2.2", 17, 50, 5000.0),
        ]
        features = extract_features(packets=packets)
        f = features[0]
        # Hiçbir değer NaN veya inf olmamalı
        for key in FEATURE_SCHEMA:
            val = f[key]
            assert val is not None, f"{key} is None"
            assert not (isinstance(val, float) and (val != val)), f"{key} is NaN"

    def test_small_large_pkt_ratio(self):
        """Küçük ve büyük paket oranları doğru hesaplanmalı."""
        packets = [
            make_mock_packet("1.1.1.1", "2.2.2.2", 6, 50, 1000.0),    # small
            make_mock_packet("1.1.1.1", "2.2.2.2", 6, 2000, 1001.0),  # large
        ]
        features = extract_features(packets=packets)
        f = features[0]
        assert f["small_pkt_ratio"] == 0.5   # 1 out of 2
        assert f["large_pkt_ratio"] == 0.5   # 1 out of 2

    def test_cross_flow_unique_counts(self):
        """Aynı kaynak IP'den farklı hedeflere giden flow'lar unique_dst sayılarını artırmalı."""
        packets = [
            make_mock_packet("10.0.0.1", "10.0.0.2", 6, 100, 1000.0),
            make_mock_packet("10.0.0.1", "10.0.0.3", 6, 100, 1000.0),
            make_mock_packet("10.0.0.1", "10.0.0.4", 17, 100, 1000.0),
        ]
        features = extract_features(packets=packets)
        # 10.0.0.1'den 3 farklı hedefe giden 3 flow
        for f in features:
            if f["src_ip"] == "10.0.0.1":
                assert f["unique_dst_ip_count"] == 3
