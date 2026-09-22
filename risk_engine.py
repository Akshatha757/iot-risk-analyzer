import json

def calculate_risk(device_data):
    """
    Calculates the cyber risk profile of an IoT device based on various input metrics.
    
    device_data is a dict containing:
        - device_type (str): camera, router, smart_bulb, smart_lock, thermostat, voice_assistant, smart_plug, smart_tv, other
        - device_name (str): user-defined name
        - manufacturer (str): manufacturer name
        - connection_type (str): Wi-Fi, Ethernet, Bluetooth, Zigbee, Z-Wave
        - default_creds_changed (bool): True if changed, False if default
        - firmware_outdated (bool): True if outdated, False if updated
        - network_isolated (bool): True if on guest network/VLAN, False if shared network
        - cloud_connected (bool): True if device sends data to cloud/internet
        - physical_access (bool): True if device is physically accessible to outsiders
        - open_ports (list/str): list of open ports, e.g. [22, 23, 80, 554, 1900]
    """
    
    score = 5  # Base minimal score, no connected device has 0 risk
    threats = []
    mitigations = set()
    
    device_type = device_data.get('device_type', 'other').lower()
    device_name = device_data.get('device_name', 'Unknown Device')
    connection_type = device_data.get('connection_type', 'Wi-Fi')
    
    default_creds_changed = device_data.get('default_creds_changed', False)
    firmware_outdated = device_data.get('firmware_outdated', False)
    network_isolated = device_data.get('network_isolated', False)
    cloud_connected = device_data.get('cloud_connected', False)
    physical_access = device_data.get('physical_access', False)
    
    # Process open ports
    ports_input = device_data.get('open_ports', [])
    if isinstance(ports_input, str):
        # Parse comma-separated string
        try:
            open_ports = [int(p.strip()) for p in ports_input.split(',') if p.strip().isdigit()]
        except Exception:
            open_ports = []
    else:
        open_ports = [int(p) for p in ports_input if str(p).strip().isdigit()]

    # 1. Credentials Check
    if not default_creds_changed:
        score += 35
        threats.append({
            'id': 'T_DEFAULT_CREDS',
            'title': 'Default Admin Credentials Active',
            'description': f'The {device_name} is using factory default credentials. Attackers regularly scan networks with databases of known manufacturer credentials (e.g. Mirai botnet vectors) to take full administrative control.',
            'impact': 'Critical',
            'category': 'Access Control'
        })
        mitigations.add('Change default credentials to a strong, unique password immediately.')
    
    # 2. Firmware Check
    if firmware_outdated:
        score += 20
        threats.append({
            'id': 'T_OUTDATED_FIRMWARE',
            'title': 'Outdated or Unpatched Firmware',
            'description': 'The device is running outdated firmware. This leaves it vulnerable to public, known exploits (CVEs) which can allow remote code execution or system takeovers.',
            'impact': 'High',
            'category': 'Vulnerability Management'
        })
        mitigations.add('Update the device firmware to the latest version and enable automatic updates if supported.')
        
    # 3. Network Isolation Check
    if not network_isolated:
        score += 15
        threats.append({
            'id': 'T_NETWORK_ISOLATION',
            'title': 'Lack of Network Segmentation',
            'description': f'The {device_name} is on the same network subnet as your personal computers and mobile devices. If this IoT device is compromised, attackers can use it as a pivot point to perform network sniffing and launch lateral attacks against your primary systems.',
            'impact': 'High',
            'category': 'Network Security'
        })
        mitigations.add('Isolate the device by placing it on a dedicated IoT VLAN or a separate guest Wi-Fi network.')

    # 4. Cloud Exposure Check
    if cloud_connected:
        if not network_isolated:
            score += 10
            threats.append({
                'id': 'T_CLOUD_EXPOSURE',
                'title': 'Direct Internet/Cloud Routing',
                'description': 'The device has an active connection to vendor cloud servers and is not network-isolated. If the cloud vendor suffers a breach or an API vulnerability, attackers can establish a reverse shell connection straight into your private home network.',
                'impact': 'Medium',
                'category': 'Network Security'
            })
        else:
            score += 5
            threats.append({
                'id': 'T_CLOUD_EXPOSURE_ISOLATED',
                'title': 'Cloud API Dependency',
                'description': 'The device communicates with external cloud APIs. While network-isolated, vendor database leaks or security flaws could expose device feeds, controls, or usage telemetry.',
                'impact': 'Low',
                'category': 'Privacy'
            })
        mitigations.add('Disable cloud control features if only local operation is needed, or protect your vendor account with Multi-Factor Authentication (MFA).')

    # 5. Open Ports Check
    if open_ports:
        port_threats = []
        for port in open_ports:
            if port == 23:  # Telnet
                score += 15
                port_threats.append('Telnet (Port 23) - Unencrypted command-line interface.')
                mitigations.add('Disable Telnet access immediately. Use SSH instead if management is required.')
            elif port == 22:  # SSH
                score += 10
                port_threats.append('SSH (Port 22) - Secure shell server is open. Vulnerable to brute force attacks.')
                mitigations.add('Disable SSH access if not needed, or restrict SSH access to specific trusted IPs and disable password authentication in favor of key-based authentication.')
            elif port == 21:  # FTP
                score += 8
                port_threats.append('FTP (Port 21) - Unencrypted file transfer protocol.')
                mitigations.add('Disable FTP and use secure file transfer protocols like SFTP or HTTPS.')
            elif port == 80:  # HTTP
                score += 5
                port_threats.append('HTTP (Port 80) - Unencrypted web administration interface.')
                mitigations.add('Access administrative portals via HTTPS (Port 443) only, and block port 80.')
            elif port == 554:  # RTSP (commonly cameras)
                score += 10
                port_threats.append('RTSP (Port 554) - Video stream protocol. If unencrypted, camera feeds can be intercepted.')
                mitigations.add('Ensure RTSP authentication is enabled and use Secure RTSP (RTSPS) if supported.')
            elif port == 1900:  # UPnP
                score += 10
                port_threats.append('UPnP (Port 1900) - Universal Plug and Play. Can allow devices to automatically punch holes through router firewalls.')
                mitigations.add('Disable UPnP on both the device and your main internet router.')
            elif port in [8080, 8000]:  # HTTP alternate
                score += 5
                port_threats.append(f'Alternate HTTP (Port {port}) - Open admin panel or service.')
                mitigations.add(f'Restrict access to administrative port {port} behind firewall rules.')
        
        if port_threats:
            threats.append({
                'id': 'T_OPEN_PORTS',
                'title': 'Exposed Network Services (Open Ports)',
                'description': f'The device has active network ports exposed: {", ".join(port_threats)}. Active ports present surface area for port scanning, service finger-printing, exploit attempts, and unauthorized administration.',
                'impact': 'High' if any(p in [23, 1900, 554] for p in open_ports) else 'Medium',
                'category': 'Surface Area Reduction'
            })

    # 6. Physical Access Check
    if physical_access:
        score += 10
        threats.append({
            'id': 'T_PHYSICAL_TAMPER',
            'title': 'Physical Access Vulnerability',
            'description': 'The device is deployed in a publicly or easily accessible physical location. Attackers can perform physical resets, access debugging interfaces (UART/JTAG pins), or extract the flash memory storage to steal credentials or firmware keys.',
            'impact': 'Medium',
            'category': 'Physical Security'
        })
        mitigations.add('Secure the device in a physical enclosure, or place it out of arm\'s reach of unauthorized visitors.')

    # 7. Device-Type Specific Vulnerabilities
    if device_type == 'camera':
        if not default_creds_changed or 554 in open_ports or 80 in open_ports:
            score += 5
            threats.append({
                'id': 'T_CAMERA_SPYING',
                'title': 'Unauthenticated Camera Feed Hijacking',
                'description': 'IP Cameras are highly targeted. Due to open RTSP/HTTP ports or default credentials, remote attackers can hijack video feeds, spying on private spaces or selling access on index websites (e.g. Insecam).',
                'impact': 'Critical',
                'category': 'Privacy'
            })
            mitigations.add('Explicitly require authentication for RTSP streams on your IP Camera settings.')
    
    elif device_type == 'router':
        if not default_creds_changed or 23 in open_ports or 80 in open_ports or 1900 in open_ports:
            score += 10
            threats.append({
                'id': 'T_ROUTER_DNS_HIJACK',
                'title': 'Gateway Takeover & DNS Hijacking',
                'description': 'As the network gateway, a compromise of the router allows malicious actors to change DNS settings, routing all local traffic through malicious servers to steal passwords and session tokens.',
                'impact': 'Critical',
                'category': 'Network Infrastructure'
            })
            mitigations.add('Disable remote management interfaces on the WAN (internet) side of the router.')
            
    elif device_type == 'smart_lock':
        if physical_access or connection_type in ['Bluetooth', 'Wi-Fi']:
            score += 5
            threats.append({
                'id': 'T_LOCK_BYPASS',
                'title': 'Physical/Wireless Lock Bypass',
                'description': 'Smart locks are susceptible to signal replay attacks (especially Bluetooth/Wi-Fi) or hardware bypass via simple physical tooling or credential spoofing.',
                'impact': 'Critical',
                'category': 'Physical Security'
            })
            mitigations.add('Verify that your smart lock uses high-grade encryption (like AES-128/256 or Bluetooth Securuty Mode 1 Level 4) and has physical anti-tamper alarms.')

    # Cap score at 100
    risk_score = min(score, 100)
    
    # Determine risk level
    if risk_score <= 30:
        risk_level = 'Low'
    elif risk_score <= 70:
        risk_level = 'Medium'
    else:
        risk_level = 'High'
        
    return {
        'score': risk_score,
        'level': risk_level,
        'threats': threats,
        'mitigations': sorted(list(mitigations))
    }
