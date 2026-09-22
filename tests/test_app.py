import json
import pytest
from app import app, db

@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    
    with app.test_client() as client:
        with app.app_context():
            db.create_all()
            yield client
            db.drop_all()

def test_index_page(client):
    """Test landing page loads HTML successfully."""
    response = client.get('/')
    assert response.status_code == 200
    assert b'IoT Shield' in response.data

def test_threat_intelligence_api(client):
    """Test fetching seeded threats."""
    from app import seed_threats
    with app.app_context():
        seed_threats()
    
    response = client.get('/api/threat-intelligence')
    assert response.status_code == 200
    data = json.loads(response.data)
    assert isinstance(data, list)

def test_analyze_and_get_scans_workflow(client):
    """Test posting a scan and retrieving dashboard stats."""
    payload = {
        'device_type': 'smart_lock',
        'device_name': 'Front Gate Lock',
        'manufacturer': 'August',
        'connection_type': 'Bluetooth',
        'default_creds_changed': True,
        'firmware_outdated': False,
        'network_isolated': True,
        'open_ports': '80'
    }
    
    # 1. Post audit scan
    post_res = client.post('/api/analyze', data=json.dumps(payload), content_type='application/json')
    assert post_res.status_code == 201
    post_data = json.loads(post_res.data)
    assert post_data['device_name'] == 'Front Gate Lock'
    scan_id = post_data['id']
    
    # 2. Get scans list
    get_res = client.get('/api/scans')
    assert get_res.status_code == 200
    scans = json.loads(get_res.data)
    assert len(scans) >= 1
    
    # 3. Get dashboard stats
    stats_res = client.get('/api/dashboard-stats')
    assert stats_res.status_code == 200
    stats = json.loads(stats_res.data)
    assert stats['total_scans'] >= 1
    
    # 4. Delete scan
    del_res = client.delete(f'/api/scans/{scan_id}')
    assert del_res.status_code == 200
