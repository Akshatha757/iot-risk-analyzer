import os
import json
from flask import Flask, render_template, request, jsonify, send_file
from models import db, ScanHistory, ThreatTemplate
from risk_engine import calculate_risk
from scanner import scan_target_ip

app = Flask(__name__)

# Configure SQLite Database (Use /tmp on Vercel serverless environment)
if os.environ.get('VERCEL') or os.environ.get('AWS_LAMBDA_FUNCTION_NAME'):
    db_path = '/tmp/iot_risk.db'
else:
    db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'iot_risk.db')

app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize DB
db.init_app(app)

# Helper function to seed threat database
def seed_threats():
    if ThreatTemplate.query.count() == 0:
        threats = [
            {
                'device_type': 'all',
                'title': 'Default Admin Credentials Vulnerability',
                'description': 'Devices shipped with default passwords (e.g. admin/admin) are scanned continuously by automated botnets. If left unchanged, anyone can gain full shell access.',
                'impact': 'Critical',
                'remediation': 'Set a unique, strong password immediately during set up.',
                'trigger_condition': 'creds_not_changed'
            },
            {
                'device_type': 'all',
                'title': 'Outdated Firmware Remote Code Execution',
                'description': 'Security vulnerabilities (CVEs) are regularly discovered in firmware. Without updates, attackers can exploit bugs to run arbitrary code and take over the device.',
                'impact': 'High',
                'remediation': 'Enable automated firmware updates or schedule manual checks monthly.',
                'trigger_condition': 'firmware_outdated'
            },
            {
                'device_type': 'all',
                'title': 'Lack of Network Segregation',
                'description': 'IoT devices sharing subnets with personal computers can be used as access points to eavesdrop on home traffic or launch attacks on local file servers.',
                'impact': 'High',
                'remediation': 'Configure a dedicated VLAN or enable client isolation on a guest Wi-Fi network.',
                'trigger_condition': 'network_not_isolated'
            },
            {
                'device_type': 'camera',
                'title': 'Unsecured RTSP Video Streams',
                'description': 'Real-Time Streaming Protocol (RTSP) on port 554 without authentication allows anyone on the internet or local network to view live camera feeds.',
                'impact': 'Critical',
                'remediation': 'Require credentials for video streams in camera advanced settings.',
                'trigger_condition': 'open_port_554'
            },
            {
                'device_type': 'router',
                'title': 'WAN Management Exposure',
                'description': 'Web administration ports (80, 443) exposed to the WAN side of the router allow remote attackers to attempt brute-force attacks on the gateway.',
                'impact': 'Critical',
                'remediation': 'Disable WAN-side management and UPnP settings in the router control panel.',
                'trigger_condition': 'open_port_80'
            },
            {
                'device_type': 'all',
                'title': 'UPnP Firewall Hole Punching',
                'description': 'Universal Plug and Play allows local devices to open port forwarding rules on the router automatically, exposing internal services to the WAN.',
                'impact': 'High',
                'remediation': 'Turn off UPnP in both the router settings and individual device configurations.',
                'trigger_condition': 'open_port_1900'
            },
            {
                'device_type': 'smart_lock',
                'title': 'Bluetooth/Wireless Relay Attacks',
                'description': 'Wireless signals can be sniffed or jammed. Bluetooth LE devices are susceptible to physical replay or range-extension hijack attempts.',
                'impact': 'Critical',
                'remediation': 'Ensure the lock uses Bluetooth Security Mode 1 Level 4 and keep hub firmware updated.',
                'trigger_condition': 'wireless_replay'
            }
        ]
        
        for t in threats:
            db.session.add(ThreatTemplate(**t))
        db.session.commit()

# Create tables and seed data
with app.app_context():
    db.create_all()
    seed_threats()

# UI Routes
@app.route('/')
def index():
    return render_template('index.html')

# API Routes
@app.route('/api/analyze', methods=['POST'])
def analyze():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No input data provided'}), 400
        
        # Calculate risk using engine
        result = calculate_risk(data)
        
        # Save to database
        scan = ScanHistory(
            device_type=data.get('device_type', 'other'),
            device_name=data.get('device_name', 'Unknown Device'),
            manufacturer=data.get('manufacturer', 'Unknown'),
            connection_type=data.get('connection_type', 'Wi-Fi'),
            firmware_version=data.get('firmware_version', '1.0'),
            default_creds_changed=data.get('default_creds_changed', False),
            network_isolated=data.get('network_isolated', False),
            cloud_connected=data.get('cloud_connected', False),
            physical_access=data.get('physical_access', False),
            open_ports=data.get('open_ports', ''),
            risk_score=result['score'],
            risk_level=result['level'],
            threats_json=json.dumps(result['threats']),
            mitigations_json=json.dumps(result['mitigations'])
        )
        
        db.session.add(scan)
        db.session.commit()
        
        return jsonify(scan.to_dict()), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Server error: {str(e)}'}), 500

@app.route('/api/scans', methods=['GET'])
def get_scans():
    try:
        scans = ScanHistory.query.order_by(ScanHistory.timestamp.desc()).all()
        return jsonify([scan.to_dict() for scan in scans]), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scans/<int:scan_id>', methods=['DELETE'])
def delete_scan(scan_id):
    try:
        scan = ScanHistory.query.get(scan_id)
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        
        db.session.delete(scan)
        db.session.commit()
        return jsonify({'message': 'Scan deleted successfully'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/dashboard-stats', methods=['GET'])
def get_dashboard_stats():
    try:
        total_scans = ScanHistory.query.count()
        if total_scans == 0:
            return jsonify({
                'total_scans': 0,
                'avg_score': 0,
                'risk_breakdown': {'Low': 0, 'Medium': 0, 'High': 0},
                'device_breakdown': {},
                'recent_scans': []
            }), 200
            
        all_scans = ScanHistory.query.all()
        avg_score = round(sum(s.risk_score for s in all_scans) / total_scans, 1)
        
        # Risk level breakdown
        low_count = ScanHistory.query.filter_by(risk_level='Low').count()
        med_count = ScanHistory.query.filter_by(risk_level='Medium').count()
        high_count = ScanHistory.query.filter_by(risk_level='High').count()
        
        # Device type breakdown
        device_breakdown = {}
        for s in all_scans:
            dtype = s.device_type.replace('_', ' ').title()
            device_breakdown[dtype] = device_breakdown.get(dtype, 0) + 1
            
        # Recent scans (last 5)
        recent = ScanHistory.query.order_by(ScanHistory.timestamp.desc()).limit(5).all()
        
        return jsonify({
            'total_scans': total_scans,
            'avg_score': avg_score,
            'risk_breakdown': {
                'Low': low_count,
                'Medium': med_count,
                'High': high_count
            },
            'device_breakdown': device_breakdown,
            'recent_scans': [s.to_dict() for s in recent]
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/threat-intelligence', methods=['GET'])
def get_threats():
    try:
        templates = ThreatTemplate.query.all()
        return jsonify([t.to_dict() for t in templates]), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/download-zip', methods=['GET'])
def download_zip():
    import zipfile
    import io
    try:
        # Create an in-memory zip file
        memory_file = io.BytesIO()
        with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zipf:
            project_dir = os.path.dirname(os.path.abspath(__file__))
            for root, dirs, files in os.walk(project_dir):
                # Exclude venv, __pycache__, and DB files
                if 'venv' in root.split(os.sep) or '__pycache__' in root.split(os.sep) or '.git' in root.split(os.sep):
                    continue
                for file in files:
                    # Don't include the active DB, or zip files
                    if file.endswith('.db') or file.endswith('.zip') or file.endswith('.pyc'):
                        continue
                    file_path = os.path.join(root, file)
                    rel_path = os.path.relpath(file_path, project_dir)
                    zipf.write(file_path, rel_path)
        
        memory_file.seek(0)
        return send_file(
            memory_file,
            mimetype='application/zip',
            as_attachment=True,
            download_name='iot-risk-analyzer.zip'
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan-ip', methods=['POST'])
def scan_ip():
    try:
        data = request.get_json() or {}
        target_ip = data.get('target_ip', '127.0.0.1').strip()
        if not target_ip:
            return jsonify({'error': 'Target IP address is required'}), 400
        
        result = scan_target_ip(target_ip)
        return jsonify(result), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)

