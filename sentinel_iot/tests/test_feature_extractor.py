"""Unit tests for the flow-based feature extractor."""

from unittest.mock import MagicMock
from monitor.feature_extractor import extract_features


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
