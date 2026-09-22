from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class ScanHistory(db.Model):
    __tablename__ = 'scan_history'
    
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    device_type = db.Column(db.String(50), nullable=False)
    device_name = db.Column(db.String(100), nullable=True)
    manufacturer = db.Column(db.String(100), nullable=True)
    connection_type = db.Column(db.String(50), nullable=False)
    firmware_version = db.Column(db.String(50), nullable=True)
    default_creds_changed = db.Column(db.Boolean, default=False)
    network_isolated = db.Column(db.Boolean, default=False)
    cloud_connected = db.Column(db.Boolean, default=False)
    physical_access = db.Column(db.Boolean, default=False)
    open_ports = db.Column(db.String(255), nullable=True)  # Comma-separated list of ports
    
    # Analysis outputs
    risk_score = db.Column(db.Integer, nullable=False)
    risk_level = db.Column(db.String(20), nullable=False)
    threats_json = db.Column(db.Text, nullable=False)  # Stored as JSON string
    mitigations_json = db.Column(db.Text, nullable=False)  # Stored as JSON string

    def to_dict(self):
        import json
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat() + 'Z' if self.timestamp else None,
            'device_type': self.device_type,
            'device_name': self.device_name,
            'manufacturer': self.manufacturer,
            'connection_type': self.connection_type,
            'firmware_version': self.firmware_version,
            'default_creds_changed': self.default_creds_changed,
            'network_isolated': self.network_isolated,
            'cloud_connected': self.cloud_connected,
            'physical_access': self.physical_access,
            'open_ports': self.open_ports,
            'risk_score': self.risk_score,
            'risk_level': self.risk_level,
            'threats': json.loads(self.threats_json),
            'mitigations': json.loads(self.mitigations_json)
        }

class ThreatTemplate(db.Model):
    __tablename__ = 'threat_templates'
    
    id = db.Column(db.Integer, primary_key=True)
    device_type = db.Column(db.String(50), nullable=False)  # 'all' or specific type like 'camera'
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=False)
    impact = db.Column(db.String(20), nullable=False)  # High, Medium, Low
    remediation = db.Column(db.Text, nullable=False)
    trigger_condition = db.Column(db.String(100), nullable=False)  # e.g., 'creds_not_changed', 'outdated_firmware'

    def to_dict(self):
        return {
            'id': self.id,
            'device_type': self.device_type,
            'title': self.title,
            'description': self.description,
            'impact': self.impact,
            'remediation': self.remediation,
            'trigger_condition': self.trigger_condition
        }
