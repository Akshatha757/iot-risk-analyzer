import pytest
from risk_engine import calculate_risk

def test_secure_device_low_risk():
    """Test a properly configured device with default creds changed and isolated network."""
    data = {
        'device_type': 'thermostat',
        'device_name': 'Living Room Thermostat',
        'manufacturer': 'Ecobee',
        'connection_type': 'Wi-Fi',
        'default_creds_changed': True,
        'firmware_outdated': False,
        'network_isolated': True,
        'cloud_connected': False,
        'physical_access': False,
        'open_ports': []
    }
    result = calculate_risk(data)
    assert result['score'] <= 30
    assert result['level'] == 'Low'
    assert len(result['threats']) == 0

def test_high_risk_device_unsecured():
    """Test an unsecured camera with default credentials, outdated firmware, and exposed Telnet/RTSP ports."""
    data = {
        'device_type': 'camera',
        'device_name': 'Front Door IP Camera',
        'manufacturer': 'Generic',
        'connection_type': 'Wi-Fi',
        'default_creds_changed': False,
        'firmware_outdated': True,
        'network_isolated': False,
        'cloud_connected': True,
        'physical_access': True,
        'open_ports': '23, 554, 80'
    }
    result = calculate_risk(data)
    assert result['score'] > 70
    assert result['level'] == 'High'
    assert any(t['id'] == 'T_DEFAULT_CREDS' for t in result['threats'])
    assert any(t['id'] == 'T_OUTDATED_FIRMWARE' for t in result['threats'])
    assert any(t['id'] == 'T_CAMERA_SPYING' for t in result['threats'])

def test_open_ports_parsing_string_and_list():
    """Test string comma-separated ports vs integer list input."""
    data_str = {
        'device_type': 'router',
        'default_creds_changed': True,
        'open_ports': '80, 1900'
    }
    data_list = {
        'device_type': 'router',
        'default_creds_changed': True,
        'open_ports': [80, 1900]
    }
    res_str = calculate_risk(data_str)
    res_list = calculate_risk(data_list)
    assert res_str['score'] == res_list['score']

def test_score_max_cap():
    """Test that risk score does not exceed 100."""
    data = {
        'device_type': 'camera',
        'default_creds_changed': False,
        'firmware_outdated': True,
        'network_isolated': False,
        'cloud_connected': True,
        'physical_access': True,
        'open_ports': [22, 23, 21, 80, 554, 1900, 8080]
    }
    result = calculate_risk(data)
    assert result['score'] == 100
    assert result['level'] == 'High'
