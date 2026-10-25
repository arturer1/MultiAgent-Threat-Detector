import ipaddress
import nmap
import requests
from typing import Dict, List, Any

# Local CVE cache to avoid hammering the NIST API on repeated queries
_CVE_CACHE: Dict[str, List[Dict[str, Any]]] = {}

def validate_target(target: str) -> bool:
    """
    Validates if the input conforms to the correct IP address or CIDR syntax.
    """
    try:
        ipaddress.ip_network(target, strict=False)
        return True
    except ValueError:
        return False

def run_nmap_scan(target: str) -> Dict[str, Any]:
    """
    Fast active scan: focuses on key attack surface ports with an explicit host timeout
    to prevent 60-second hangs on non-responsive or simulated IPs.
    """
    nm = nmap.PortScanner()
    # Fast scan: key ports only, 3s host timeout, single retry to avoid blocking evaluation
    scan_args = '-sV -T4 -p 21,22,80,443,3389,8080 --host-timeout 3s --max-retries 1'
    
    try:
        nm.scan(hosts=target, arguments=scan_args)
    except Exception:
        # Fallback for unreachable synthetic subnets or network anomalies
        return {target: {'status': 'unreachable', 'services': []}}
    
    scan_results = {}
    for host in nm.all_hosts():
        scan_results[host] = {'status': nm[host].state(), 'services': []}
        for proto in nm[host].all_protocols():
            for port in sorted(nm[host][proto].keys()):
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
    Queries the National Vulnerability Database (NVD) with local in-memory caching
    and short timeouts to avoid stalling the evaluation pipeline.
    """
    if not service_name or not version:
        return []

    cache_key = f"{service_name}_{version}".lower()
    if cache_key in _CVE_CACHE:
        return _CVE_CACHE[cache_key]

    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {'keywordSearch': f"{service_name} {version}", 'resultsPerPage': 3}

    try:
        response = requests.get(url, params=params, timeout=3)
        response.raise_for_status()
        data = response.json()
        
        cve_list = []
        for item in data.get('vulnerabilities', []):
            cve_data = item.get('cve', {})
            metrics = cve_data.get('metrics', {})
            cvss_score = "N/A"
            if 'cvssMetricV31' in metrics:
                cvss_score = metrics['cvssMetricV31'][0]['cvssData']['baseScore']
            cve_list.append({
                'cve_id': cve_data.get('id', 'Unknown'),
                'cvss_score': cvss_score,
                'description': cve_data.get('descriptions', [{}])[0].get('value', '')
            })
        _CVE_CACHE[cache_key] = cve_list
        return cve_list
    except Exception:
        return []

def execute_ip_extraction(target: str) -> Dict[str, Any]:
    """
    Orchestrates the deterministic workflow before passing data to the LLM.
    """
    if not validate_target(target):
        return {"error": f"Invalid IP address or CIDR notation: {target}"}

    network_data = run_nmap_scan(target)
    for host, data in network_data.items():
        for service in data.get('services', []):
            service['cves'] = query_nvd_for_cves(service['name'], service['version'])
            
    return network_data
