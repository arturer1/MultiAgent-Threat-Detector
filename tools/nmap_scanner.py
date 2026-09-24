import ipaddress
import nmap
import requests
from typing import Dict, List, Any, Optional

def validate_target(target: str) -> bool:
    """
    Validates if the input conforms to the correct IP address or CIDR syntax.
    """
    try:
        # Check if it's a valid individual IP or a valid network CIDR (e.g., 192.168.14.0/24)
        ipaddress.ip_network(target, strict=False)
        return True
    except ValueError:
        return False

def run_nmap_scan(target: str) -> Dict[str, Any]:
    """
    Automates the discovery of active nodes, identifying open ports and 
    running services within the specified address range[cite: 1].
    """
    nm = nmap.PortScanner()
    # -sV enables service/version detection required for NVD matching
    nm.scan(hosts=target, arguments='-sV -T4')
    
    scan_results = {}
    for host in nm.all_hosts():
        scan_results[host] = {'status': nm[host].state(), 'services': []}
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in sorted(ports):
                service_info = nm[host][proto][port]
                scan_results[host]['services'].append({
                    'port': port,
                    'protocol': proto,
                    'name': service_info.get('name', 'unknown'),
                    'version': service_info.get('version', '')
                })
    return scan_results

def query_nvd_for_cves(service_name: str, version: str) -> List[Dict[str, Any]]:
    """
    Queries the National Vulnerability Database (NVD) to extract known common 
    vulnerabilities and exposures (CVEs), including CVSS scores and risk vectors[cite: 1].
    """
    if not service_name or not version:
        return []

    # The NVD API endpoint for CVEs
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    # Query parameters using CPE (Common Platform Enumeration) matching or keywords
    keyword = f"{service_name} {version}"
    params = {
        'keywordSearch': keyword,
        'resultsPerPage': 5 # Limit to top 5 to prevent context window overflow
    }

    try:
        response = requests.get(url, params=params, timeout=10)
        response.raise_for_status()
        data = response.json()
        
        cve_list = []
        for item in data.get('vulnerabilities', []):
            cve_data = item.get('cve', {})
            cve_id = cve_data.get('id', 'Unknown')
            metrics = cve_data.get('metrics', {})
            
            # Extract CVSS v3.1 score if available
            cvss_score = "N/A"
            if 'cvssMetricV31' in metrics:
                cvss_score = metrics['cvssMetricV31'][0]['cvssData']['baseScore']

            cve_list.append({
                'cve_id': cve_id,
                'cvss_score': cvss_score,
                'description': cve_data.get('descriptions', [{}])[0].get('value', '')
            })
        return cve_list
    except requests.RequestException:
        return []

def execute_ip_extraction(target: str) -> Dict[str, Any]:
    """
    Orchestrates the deterministic workflow before passing data to the LLM[cite: 1].
    """
    if not validate_target(target):
        return {"error": f"Invalid IP address or CIDR notation: {target}"}

    network_data = run_nmap_scan(target)
    
    # Enrich the scan results with NVD metadata[cite: 1]
    for host, data in network_data.items():
        for service in data['services']:
            service['cves'] = query_nvd_for_cves(service['name'], service['version'])
            
    return network_data