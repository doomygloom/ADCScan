#!/usr/bin/env python3
# X: @owldecoy

import argparse
import concurrent.futures
import sys
import ldap3
import requests
import socket
import logging
from typing import List, Set
from urllib.parse import urljoin
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def read_ip_file(file_path: str) -> List[str]:
    try:
        with open(file_path, 'r') as f:
            ips = [line.strip() for line in f if line.strip()]
            valid_ips = []
            for ip in ips:
                try:
                    socket.inet_aton(ip)
                    valid_ips.append(ip)
                except socket.error:
                    logger.warning(f"Invalid IP address found and skipped: {ip}")
            return valid_ips
    except FileNotFoundError:
        logger.error(f"IP file not found: {file_path}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Error reading IP file: {e}")
        sys.exit(1)

def check_adcs_server_ldap(ip: str, timeout: int = 5, username: str = None, password: str = None) -> tuple:
    try:
        server = ldap3.Server(ip, port=389, get_info=ldap3.ALL, connect_timeout=timeout)
        if username and password:
            conn = ldap3.Connection(server, user=username, password=password, auto_bind=True)
        else:
            conn = ldap3.Connection(server, auto_bind=True, authentication=ldap3.ANONYMOUS)

        search_filter = '(objectClass=pKIEnrollmentService)'
        base_dn = server.info.other.get('defaultNamingContext', [''])[0]
        if not base_dn:
            logger.debug(f"No default naming context found for {ip}")
            return ip, False, None

        conn.search(
            search_base=base_dn,
            search_filter=search_filter,
            search_scope=ldap3.SUBTREE,
            attributes=['cn', 'dNSHostName']
        )

        if conn.entries:
            adcs_servers = [entry.dNSHostName.value or entry.cn.value for entry in conn.entries if entry.dNSHostName or entry.cn]
            logger.info(f"ADCS server found at {ip} (LDAP): {', '.join(adcs_servers)}")
            return ip, True, conn
        else:
            logger.debug(f"No ADCS server found at {ip} (LDAP)")
            return ip, False, None

    except ldap3.core.exceptions.LDAPSocketOpenError:
        logger.debug(f"Could not connect to {ip} (LDAP port 389)")
        return ip, False, None
    except ldap3.core.exceptions.LDAPBindError:
        logger.error(f"Authentication failed for {ip}")
        return ip, False, None
    except Exception as e:
        logger.error(f"Error checking {ip} (LDAP): {e}")
        return ip, False, None

def check_adcs_server_http(ip: str, timeout: int = 5, use_https: bool = False) -> tuple:
    protocol = 'https' if use_https else 'http'
    base_url = f"{protocol}://{ip}"
    endpoints = [
        '/certsrv/',
        '/ADPolicyProvider_CEP_UsernamePassword/service.svc',
        '/ADPolicyProvider_CEP_Kerberos/service.svc',
    ]

    try:
        for endpoint in endpoints:
            url = urljoin(base_url, endpoint)
            response = requests.get(url, timeout=timeout, verify=False)
            if response.status_code in [200, 401, 403]:
                logger.info(f"ADCS server found at {ip} (HTTP): {url}")
                return ip, True, None
            elif response.status_code == 404:
                continue
        logger.debug(f"No ADCS server found at {ip} (HTTP)")
        return ip, False, None

    except requests.exceptions.RequestException as e:
        logger.debug(f"Could not connect to {ip} (HTTP): {e}")
        return ip, False, None
    except Exception as e:
        logger.error(f"Error checking {ip} (HTTP): {e}")
        return ip, False, None

def check_esc_vulnerabilities(ip: str, conn: ldap3.Connection, base_dn: str) -> List[str]:
    vulnerabilities = []
    try:
        template_filter = '(objectClass=pKICertificateTemplate)'
        conn.search(
            search_base=f'CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,{base_dn}',
            search_filter=template_filter,
            search_scope=ldap3.SUBTREE,
            attributes=[
                'cn', 'msPKI-Certificate-Name-Flag', 'pKIExtendedKeyUsage', 'msPKI-Enrollment-Flag',
                'msPKI-Certificate-Application-Policy', 'nTSecurityDescriptor', 'msPKI-RA-Signature'
            ]
        )

        for entry in conn.entries:
            template_name = entry.cn.value
            # ESC1: Certificate template allows SAN specification by enrollee
            if hasattr(entry, 'msPKI-Certificate-Name-Flag'):
                flags = int(entry['msPKI-Certificate-Name-Flag'].value or 0)
                if flags & 0x00000001: # CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT
                    vulnerabilities.append(f"ESC1 on {ip}: Template '{template_name}' allows enrollee-supplied SAN")

            # ESC2: Template allows any purpose EKU or no EKU
            if hasattr(entry, 'pKIExtendedKeyUsage'):
                ekus = entry['pKIExtendedKeyUsage'].values or []
                if not ekus or '2.5.29.37.0' in ekus: # Any Purpose OID
                    vulnerabilities.append(f"ESC2 on {ip}: Template '{template_name}' has Any Purpose EKU or no EKU")

            # ESC3: Template has dangerous application policies (e.g., Client Authentication)
            if hasattr(entry, 'msPKI-Certificate-Application-Policy'):
                app_policies = entry['msPKI-Certificate-Application-Policy'].values or []
                dangerous_ekus = ['1.3.6.1.5.5.7.3.2', '1.3.6.1.4.1.311.20.2.2'] # Client Auth, Smartcard Logon
                if any(eku in app_policies for eku in dangerous_ekus):
                    vulnerabilities.append(f"ESC3 on {ip}: Template '{template_name}' allows dangerous application policies")

            # ESC4: Low-privileged users have edit rights on template
            # Note: Parsing nTSecurityDescriptor requires complex DACL analysis. this has been simplified.
            if hasattr(entry, 'nTSecurityDescriptor'):
                vulnerabilities.append(f"ESC4 on {ip}: Template '{template_name}' requires DACL analysis (manual check needed)")

            # ESC5: Template allows auto-enrollment
            if hasattr(entry, 'msPKI-Enrollment-Flag'):
                enroll_flags = int(entry['msPKI-Enrollment-Flag'].value or 0)
                if not (enroll_flags & 0x00000020): # CT_FLAG_NO_SECURITY_EXTENSION not set
                    vulnerabilities.append(f"ESC5 on {ip}: Template '{template_name}' may allow auto-enrollment")

            # ESC6: Template requires no manager approval but allows dangerous usage
            if hasattr(entry, 'msPKI-RA-Signature'):
                signatures = int(entry['msPKI-RA-Signature'].value or 0)
                if signatures == 0 and hasattr(entry, 'pKIExtendedKeyUsage'):
                    ekus = entry['pKIExtendedKeyUsage'].values or []
                    if any(eku in ['1.3.6.1.5.5.7.3.2', '2.5.29.37.0'] for eku in ekus):
                        vulnerabilities.append(f"ESC6 on {ip}: Template '{template_name}' requires no approval and allows dangerous usage")                                                                                                                       

            # ESC8: Misconfigured enrollment agent restrictions
            # Simplified: Check for enrollment agent EKU
            if hasattr(entry, 'pKIExtendedKeyUsage'):
                if '1.3.6.1.4.1.311.20.2.1' in entry['pKIExtendedKeyUsage'].values:
                    vulnerabilities.append(f"ESC8 on {ip}: Template '{template_name}' allows certificate agent enrollment")

    except Exception as e:
        logger.error(f"Error checking ESC vulnerabilities on {ip}: {e}")
    
    return vulnerabilities

def check_esc7(ip: str, timeout: int = 5, use_https: bool = False) -> List[str]:
    """Check for ESC7: Unauthenticated access to web enrollment."""
    vulnerabilities = []
    protocol = 'https' if use_https else 'http'
    url = f"{protocol}://{ip}/certsrv/"

    try:
        response = requests.get(url, timeout=timeout, verify=False)
        if response.status_code == 200:
            # Check if the page contains signs of web enrollment without auth
            if 'Request a certificate' in response.text or 'Microsoft Active Directory Certificate Services' in response.text:
                vulnerabilities.append(f"ESC7 on {ip}: Unauthenticated web enrollment accessible at {url}")
        elif response.status_code in [401, 403]:
            logger.debug(f"Web enrollment at {ip} requires authentication (not ESC7)")
        else:
            logger.debug(f"No web enrollment found at {ip} for ESC7: {response.status_code}")
    except requests.exceptions.RequestException as e:
        logger.debug(f"Could not connect to {ip} for ESC7: {e}")
    except Exception as e:
        logger.error(f"Error checking ESC7 on {ip}: {e}")

    return vulnerabilities

def scan_ips(ips: List[str], method: str = 'ldap', timeout: int = 5, max_workers: int = 50,
             use_https: bool = False, username: str = None, password: str = None) -> tuple:
    adcs_ips = set()
    vulnerabilities = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        if method == 'http':
            future_to_ip = {
                executor.submit(check_adcs_server_http, ip, timeout, use_https): ip for ip in ips
            }
        else: # method == 'ldap'
            future_to_ip = {
                executor.submit(check_adcs_server_ldap, ip, timeout, username, password): ip for ip in ips
            }

        for future in concurrent.futures.as_completed(future_to_ip):
            ip = future_to_ip[future]
            conn = None
            try:
                ip, is_adcs, conn = future.result()
                if is_adcs:
                    adcs_ips.add(ip)
                    esc7_vulns = check_esc7(ip, timeout, use_https)
                    vulnerabilities.extend(esc7_vulns)
                    if conn and username and password:
                        base_dn = conn.server.info.other.get('defaultNamingContext', [''])[0]
                        if base_dn:
                            esc_vulns = check_esc_vulnerabilities(ip, conn, base_dn)
                            vulnerabilities.extend(esc_vulns)
            except Exception as e:
                logger.error(f"Error processing {ip}: {e}")
            finally:
                if conn and conn.bound:
                    conn.unbind()

    return adcs_ips, vulnerabilities


def main():
    parser = argparse.ArgumentParser(description="Identify ADCS servers and check for ESC1–ESC8 vulnerabilities.")
    parser.add_argument('ip_file', help="File containing IP addresses (one per line)")
    parser.add_argument('--method', choices=['ldap', 'http'], default='ldap',
                        help="Scanning method: 'ldap' (default) or 'http'")
    parser.add_argument('--timeout', type=int, default=5, help="Connection timeout in seconds (default: 5)")
    parser.add_argument('--workers', type=int, default=50, help="Maximum number of concurrent workers (default: 50)")
    parser.add_argument('--https', action='store_true', help="Use HTTPS instead of HTTP for HTTP method and ESC7")
    parser.add_argument('--username', help="LDAP username (e.g., domain\\user) for ESC1–ESC6, ESC8 checks")
    parser.add_argument('--password', help="LDAP password for ESC1–ESC6, ESC8 checks")
    args = parser.parse_args()

    logger.info(f"Reading IP addresses from {args.ip_file}")
    ips = read_ip_file(args.ip_file)
    if not ips:
        logger.error("No valid IP addresses found in the file.")
        sys.exit(1)
    
    logger.info(f"Scanning {len(ips)} IP addresses for ADCS servers using {args.method.upper()} method...")
    
    adcs_ips, vulnerabilities = scan_ips(
        ips, method=args.method, timeout=args.timeout, max_workers=args.workers,
        use_https=args.https, username=args.username, password=args.password
    )
    
    if adcs_ips:
        logger.info("\nADCS servers found at the following IPs:")
        for ip in sorted(adcs_ips):
            print(ip)
    else:
        logger.info("\nNo ADCS servers found.")
    
    if vulnerabilities:
        logger.info("\nVulnerabilities found:")
        for vuln in vulnerabilities:
            print(vuln)
    else:
        logger.info("\nNo ESC vulnerabilities found.")
    
    logger.info(f"Scan completed. Found {len(adcs_ips)} ADCS servers and {len(vulnerabilities)} vulnerabilities out of {len(ips)} IPs.")                                                                                                                          

if __name__ == "__main__":
    
    main()
