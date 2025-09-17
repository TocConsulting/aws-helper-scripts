#!/usr/bin/env python3
"""
ELB/ALB Security Auditor - Lambda Version
Serverless function for automated load balancer security auditing
"""

import json
import boto3
import os
import threading
import ssl
import socket
from queue import Queue
from concurrent.futures import ThreadPoolExecutor, as_completed
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError
from typing import List, Dict, Optional, Any, Tuple
from datetime import datetime, timedelta
import logging

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Comprehensive list of AWS regions as of 2024
AWS_REGIONS = [
    # US East (N. Virginia, Ohio)
    'us-east-1', 'us-east-2',
    # US West (N. California, Oregon)
    'us-west-1', 'us-west-2',
    # Africa (Cape Town)
    'af-south-1',
    # Asia Pacific (Hong Kong, Hyderabad, Jakarta, Melbourne, Mumbai, Osaka, Seoul, Singapore, Sydney, Tokyo)
    'ap-east-1', 'ap-south-1', 'ap-south-2', 'ap-southeast-1', 'ap-southeast-2', 
    'ap-southeast-3', 'ap-southeast-4', 'ap-northeast-1', 'ap-northeast-2', 'ap-northeast-3',
    # Canada (Central, West)
    'ca-central-1', 'ca-west-1',
    # Europe (Frankfurt, Ireland, London, Milan, Paris, Spain, Stockholm, Zurich)
    'eu-central-1', 'eu-central-2', 'eu-west-1', 'eu-west-2', 'eu-west-3', 
    'eu-south-1', 'eu-south-2', 'eu-north-1',
    # Middle East (Bahrain, UAE)
    'me-south-1', 'me-central-1',
    # South America (São Paulo)
    'sa-east-1',
    # Israel (Tel Aviv)
    'il-central-1',
]

def get_all_regions() -> List[str]:
    """Get all AWS regions where ELB is available."""
    return AWS_REGIONS

def analyze_ssl_certificate(cert_arn: str, region: str) -> Dict:
    """Analyze SSL certificate for security issues."""
    issues = []
    
    try:
        acm_client = boto3.client('acm', region_name=region)
        cert = acm_client.describe_certificate(CertificateArn=cert_arn)['Certificate']
        
        # Check expiration
        expiry = cert.get('NotAfter')
        if expiry:
            days_until_expiry = (expiry.replace(tzinfo=None) - datetime.now()).days
            if days_until_expiry < 30:
                issues.append({
                    'severity': 'HIGH',
                    'issue': f'Certificate expires in {days_until_expiry} days',
                    'certificate_arn': cert_arn,
                    'expiry_date': expiry.isoformat()
                })
            elif days_until_expiry < 90:
                issues.append({
                    'severity': 'MEDIUM',
                    'issue': f'Certificate expires in {days_until_expiry} days',
                    'certificate_arn': cert_arn,
                    'expiry_date': expiry.isoformat()
                })
        
        # Check validation status
        if cert.get('Status') != 'ISSUED':
            issues.append({
                'severity': 'CRITICAL',
                'issue': f'Certificate status: {cert.get("Status")}',
                'certificate_arn': cert_arn
            })
        
        # Check key algorithm and size
        key_algorithm = cert.get('KeyAlgorithm', 'Unknown')
        key_usage = cert.get('KeyUsages', [])
        
        if key_algorithm == 'RSA-1024':
            issues.append({
                'severity': 'HIGH',
                'issue': 'Weak RSA-1024 key detected',
                'certificate_arn': cert_arn
            })
        
        # Check subject alternative names
        san_count = len(cert.get('SubjectAlternativeNames', []))
        domain_name = cert.get('DomainName', 'Unknown')
        
        return {
            'certificate_arn': cert_arn,
            'status': cert.get('Status', 'Unknown'),
            'domain_name': domain_name,
            'subject_alternative_names': san_count,
            'key_algorithm': key_algorithm,
            'key_usage': [usage.get('Name') for usage in key_usage],
            'expiry_date': expiry.isoformat() if expiry else None,
            'days_until_expiry': days_until_expiry if expiry else None,
            'issues': issues
        }
        
    except Exception as e:
        issues.append({
            'severity': 'MEDIUM',
            'issue': f'Unable to analyze certificate: {str(e)}',
            'certificate_arn': cert_arn
        })
        return {
            'certificate_arn': cert_arn,
            'status': 'ERROR',
            'issues': issues,
            'error': str(e)
        }

def check_tls_versions(hostname: str, port: int = 443, timeout: int = 10) -> Dict:
    """Check supported TLS versions for a hostname."""
    if not hostname or hostname == 'Unknown':
        return {
            'supported_versions': [],
            'deprecated_versions': [],
            'error': 'Invalid hostname'
        }
    
    supported_versions = []
    deprecated_versions = []
    
    # TLS versions to test (newest to oldest)
    tls_versions = [
        ('TLS 1.3', ssl.PROTOCOL_TLS),
        ('TLS 1.2', ssl.PROTOCOL_TLS),
        ('TLS 1.1', ssl.PROTOCOL_TLS),
        ('TLS 1.0', ssl.PROTOCOL_TLS),
    ]
    
    try:
        for version_name, protocol in tls_versions:
            try:
                context = ssl.create_default_context()
                
                # Configure specific TLS version
                if version_name == 'TLS 1.3':
                    context.minimum_version = ssl.TLSVersion.TLSv1_3
                    context.maximum_version = ssl.TLSVersion.TLSv1_3
                elif version_name == 'TLS 1.2':
                    context.minimum_version = ssl.TLSVersion.TLSv1_2
                    context.maximum_version = ssl.TLSVersion.TLSv1_2
                elif version_name == 'TLS 1.1':
                    context.minimum_version = ssl.TLSVersion.TLSv1_1
                    context.maximum_version = ssl.TLSVersion.TLSv1_1
                elif version_name == 'TLS 1.0':
                    context.minimum_version = ssl.TLSVersion.TLSv1
                    context.maximum_version = ssl.TLSVersion.TLSv1
                
                with socket.create_connection((hostname, port), timeout=timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        supported_versions.append(version_name)
                        
                        # Mark deprecated versions
                        if version_name in ['TLS 1.0', 'TLS 1.1']:
                            deprecated_versions.append(version_name)
                            
            except (ssl.SSLError, socket.error, OSError):
                # Version not supported or connection failed
                continue
                
    except Exception as e:
        return {
            'supported_versions': [],
            'deprecated_versions': [],
            'error': f'TLS version check failed: {str(e)}'
        }
    
    return {
        'supported_versions': supported_versions,
        'deprecated_versions': deprecated_versions,
        'has_deprecated_tls': len(deprecated_versions) > 0
    }

def analyze_ssl_configuration(load_balancer: Dict, listeners: List[Dict], region: str) -> List[Dict]:
    """Comprehensive SSL/TLS analysis for load balancer."""
    ssl_issues = []
    
    try:
        hostname = load_balancer.get('DNSName', load_balancer.get('dns_name'))
        
        # Analyze each HTTPS listener
        for listener in listeners:
            protocol = listener.get('Protocol', '').upper()
            port = listener.get('Port', 443)
            
            if protocol == 'HTTPS':
                # Get SSL certificate details
                certificates = listener.get('Certificates', [])
                
                for cert_info in certificates:
                    cert_arn = cert_info.get('CertificateArn')
                    if cert_arn:
                        cert_analysis = analyze_ssl_certificate(cert_arn, region)
                        ssl_issues.extend(cert_analysis.get('issues', []))
                
                # Check TLS versions if we have a hostname
                if hostname and hostname != 'Unknown':
                    try:
                        tls_analysis = check_tls_versions(hostname, port)
                        
                        if tls_analysis.get('has_deprecated_tls'):
                            ssl_issues.append({
                                'severity': 'HIGH',
                                'issue': f'Deprecated TLS versions supported: {", ".join(tls_analysis["deprecated_versions"])}',
                                'hostname': hostname,
                                'port': port
                            })
                        
                        if not tls_analysis.get('supported_versions'):
                            ssl_issues.append({
                                'severity': 'MEDIUM',
                                'issue': 'Unable to determine supported TLS versions',
                                'hostname': hostname,
                                'port': port
                            })
                        elif 'TLS 1.2' not in tls_analysis.get('supported_versions', []) and 'TLS 1.3' not in tls_analysis.get('supported_versions', []):
                            ssl_issues.append({
                                'severity': 'CRITICAL',
                                'issue': 'No modern TLS versions (1.2+) supported',
                                'hostname': hostname,
                                'port': port
                            })
                    except Exception as e:
                        ssl_issues.append({
                            'severity': 'LOW',
                            'issue': f'TLS version check failed: {str(e)}',
                            'hostname': hostname,
                            'port': port
                        })
        
        return ssl_issues
        
    except Exception as e:
        logger.warning(f"SSL configuration analysis failed: {e}")
        return [{
            'severity': 'LOW',
            'issue': f'SSL analysis failed: {str(e)}'
        }]

def is_public(elb: Dict) -> bool:
    """Check if load balancer is publicly accessible."""
    return elb.get('Scheme', '') == 'internet-facing'

def is_insecure_listener(listener: Dict) -> bool:
    """Check if listener uses insecure protocol."""
    # Handle both ALB/NLB format and Classic ELB format
    protocol = listener.get('Protocol', listener.get('protocol', '')).upper()
    port = listener.get('Port', listener.get('load_balancer_port', 0))
    
    # HTTP listeners are generally insecure
    if protocol == 'HTTP':
        return True
    
    # Common insecure ports
    insecure_ports = [80, 8080, 8000, 3000]
    if port in insecure_ports and protocol != 'HTTPS':
        return True
    
    return False

def analyze_classic_elb_security(elb: Dict, listeners: List[Dict], region: str) -> Dict:
    """Analyze security of Classic ELB."""
    findings = []
    severity = 'info'
    ssl_issues = []
    
    # Check if publicly accessible
    if is_public(elb):
        findings.append("Publicly accessible ELB detected")
        severity = 'warning'
    
    # Check listeners for security issues
    insecure_listeners = []
    https_listeners = []
    
    for listener in listeners:
        if is_insecure_listener(listener):
            protocol = listener.get('protocol', 'Unknown')
            port = listener.get('load_balancer_port', 'Unknown')
            insecure_listeners.append(f"{protocol} on port {port}")
            severity = 'warning'
        
        # Collect HTTPS listeners for SSL analysis
        if listener.get('protocol', '').upper() == 'HTTPS':
            https_listeners.append(listener)
    
    if insecure_listeners:
        findings.append(f"Insecure listeners: {', '.join(insecure_listeners)}")
    
    # Perform SSL/TLS analysis for HTTPS listeners
    if https_listeners:
        ssl_issues = analyze_ssl_configuration(elb, https_listeners, region)
        
        # Escalate severity based on SSL issues
        for issue in ssl_issues:
            if issue.get('severity') == 'CRITICAL':
                severity = 'critical'
                break
            elif issue.get('severity') == 'HIGH' and severity != 'critical':
                severity = 'warning'
        
        # Add SSL findings to main findings
        for issue in ssl_issues:
            findings.append(f"SSL/TLS Issue: {issue.get('issue', 'Unknown issue')}")
    
    return {
        'severity': severity,
        'findings': findings,
        'is_public': is_public(elb),
        'insecure_listeners': len(insecure_listeners),
        'ssl_issues': ssl_issues,
        'https_listeners': len(https_listeners)
    }

def analyze_target_health(elbv2_client, target_group_arn: str) -> Dict:
    """Analyze target group health."""
    try:
        response = elbv2_client.describe_target_health(TargetGroupArn=target_group_arn)
        targets = response.get('TargetHealthDescriptions', [])
        
        healthy_targets = []
        unhealthy_targets = []
        
        for target in targets:
            target_id = target.get('Target', {}).get('Id', 'Unknown')
            health_state = target.get('TargetHealth', {}).get('State', 'unknown')
            
            if health_state == 'healthy':
                healthy_targets.append(target_id)
            else:
                unhealthy_targets.append({
                    'id': target_id,
                    'state': health_state,
                    'reason': target.get('TargetHealth', {}).get('Reason', 'Unknown')
                })
        
        return {
            'total_targets': len(targets),
            'healthy_targets': len(healthy_targets),
            'unhealthy_targets': len(unhealthy_targets),
            'unhealthy_details': unhealthy_targets[:5]  # Limit for response size
        }
    except ClientError as e:
        logger.warning(f"Error checking target health for {target_group_arn}: {e}")
        return {
            'total_targets': 0,
            'healthy_targets': 0,
            'unhealthy_targets': 0,
            'error': str(e)
        }

def analyze_alb_nlb_security(lb: Dict, listeners: List[Dict], elbv2_client, region: str) -> Dict:
    """Analyze security of ALB/NLB."""
    findings = []
    severity = 'info'
    target_groups_health = []
    ssl_issues = []
    
    # Check if publicly accessible
    if is_public(lb):
        findings.append("Publicly accessible ALB/NLB detected")
        severity = 'warning'
    
    # Check listeners for security issues
    insecure_listeners = []
    https_listeners = []
    
    for listener in listeners:
        if is_insecure_listener(listener):
            protocol = listener.get('Protocol', 'Unknown')
            port = listener.get('Port', 'Unknown')
            insecure_listeners.append(f"{protocol} on port {port}")
            severity = 'warning'
        
        # Collect HTTPS listeners for SSL analysis
        if listener.get('Protocol', '').upper() == 'HTTPS':
            https_listeners.append(listener)
        
        # Check target groups for this listener
        default_actions = listener.get('DefaultActions', [])
        for action in default_actions:
            if action.get('Type') == 'forward':
                target_group_arn = action.get('TargetGroupArn')
                if target_group_arn:
                    health_info = analyze_target_health(elbv2_client, target_group_arn)
                    target_groups_health.append({
                        'target_group_arn': target_group_arn,
                        'health': health_info
                    })
                    
                    # Check for unhealthy targets
                    if health_info.get('unhealthy_targets', 0) > 0:
                        findings.append(f"Unhealthy targets detected in target group")
                        if severity == 'info':
                            severity = 'warning'
    
    if insecure_listeners:
        findings.append(f"Insecure listeners: {', '.join(insecure_listeners)}")
    
    # Perform SSL/TLS analysis for HTTPS listeners
    if https_listeners:
        ssl_issues = analyze_ssl_configuration(lb, https_listeners, region)
        
        # Escalate severity based on SSL issues
        for issue in ssl_issues:
            if issue.get('severity') == 'CRITICAL':
                severity = 'critical'
                break
            elif issue.get('severity') == 'HIGH' and severity != 'critical':
                severity = 'warning'
        
        # Add SSL findings to main findings
        for issue in ssl_issues:
            findings.append(f"SSL/TLS Issue: {issue.get('issue', 'Unknown issue')}")
    
    return {
        'severity': severity,
        'findings': findings,
        'is_public': is_public(lb),
        'insecure_listeners': len(insecure_listeners),
        'target_groups_health': target_groups_health,
        'ssl_issues': ssl_issues,
        'https_listeners': len(https_listeners)
    }

def audit_load_balancers_in_region(region: str, scan_all_regions_flag: bool) -> Dict:
    """Audit load balancers in a specific region."""
    try:
        # Create clients for this region
        elb_client = boto3.client('elb', region_name=region)
        elbv2_client = boto3.client('elbv2', region_name=region)
        
        logger.info(f"Auditing load balancers in region: {region}")
        
        region_results = {
            'region': region,
            'classic_elbs': [],
            'alb_nlbs': [],
            'total_load_balancers': 0,
            'public_load_balancers': 0,
            'insecure_listeners': 0,
            'critical_findings': 0,
            'warnings': 0,
            'errors': []
        }
        
        # Audit Classic ELBs
        try:
            classic_response = elb_client.describe_load_balancers()
            classic_elbs = classic_response.get('LoadBalancerDescriptions', [])
            
            for elb in classic_elbs:
                lb_name = elb.get('LoadBalancerName', 'Unknown')
                listeners = elb.get('ListenerDescriptions', [])
                
                # Extract detailed listener info
                listener_details = []
                for listener_desc in listeners:
                    listener = listener_desc.get('Listener', {})
                    listener_info = {
                        'protocol': listener.get('Protocol'),
                        'load_balancer_port': listener.get('LoadBalancerPort'),
                        'instance_port': listener.get('InstancePort'),
                        'instance_protocol': listener.get('InstanceProtocol'),
                        'ssl_certificate_id': listener.get('SSLCertificateId')
                    }
                    listener_details.append(listener_info)
                
                # Get health check information
                health_check = elb.get('HealthCheck', {})
                health_check_info = {
                    'target': health_check.get('Target'),
                    'interval': health_check.get('Interval'),
                    'timeout': health_check.get('Timeout'),
                    'healthy_threshold': health_check.get('HealthyThreshold'),
                    'unhealthy_threshold': health_check.get('UnhealthyThreshold')
                }
                
                # Security analysis
                security_analysis = analyze_classic_elb_security(elb, listener_details, region)
                
                elb_info = {
                    'name': lb_name,
                    'type': 'classic',
                    'scheme': elb.get('Scheme', 'Unknown'),
                    'dns_name': elb.get('DNSName', 'Unknown'),
                    'canonical_hosted_zone_name': elb.get('CanonicalHostedZoneName', 'Unknown'),
                    'canonical_hosted_zone_name_id': elb.get('CanonicalHostedZoneNameID', 'Unknown'),
                    'created_time': elb.get('CreatedTime').isoformat() if elb.get('CreatedTime') else None,
                    'vpc_id': elb.get('VPCId'),
                    'subnets': elb.get('Subnets', []),
                    'availability_zones': elb.get('AvailabilityZones', []),
                    'security_groups': elb.get('SecurityGroups', []),
                    'source_security_group': elb.get('SourceSecurityGroup', {}),
                    'instances': [inst.get('InstanceId') for inst in elb.get('Instances', [])],
                    'health_check': health_check_info,
                    'listeners': listener_details,
                    'listener_count': len(listeners),
                    'security_analysis': security_analysis
                }
                
                region_results['classic_elbs'].append(elb_info)
                
                # Update counters
                if security_analysis['is_public']:
                    region_results['public_load_balancers'] += 1
                region_results['insecure_listeners'] += security_analysis['insecure_listeners']
                
                if security_analysis['severity'] == 'critical':
                    region_results['critical_findings'] += 1
                elif security_analysis['severity'] == 'warning':
                    region_results['warnings'] += 1
                    
        except ClientError as e:
            if e.response['Error']['Code'] not in ['UnauthorizedOperation', 'AccessDenied']:
                logger.warning(f"Error retrieving Classic ELBs in {region}: {e}")
                region_results['errors'].append(f"Classic ELB error: {e.response['Error']['Message']}")
        
        # Audit ALBs/NLBs
        try:
            alb_response = elbv2_client.describe_load_balancers()
            alb_nlbs = alb_response.get('LoadBalancers', [])
            
            for lb in alb_nlbs:
                lb_arn = lb.get('LoadBalancerArn')
                lb_name = lb.get('LoadBalancerName', 'Unknown')
                
                # Get listeners
                listeners_response = elbv2_client.describe_listeners(LoadBalancerArn=lb_arn)
                listeners = listeners_response.get('Listeners', [])
                
                # Security analysis
                security_analysis = analyze_alb_nlb_security(lb, listeners, elbv2_client, region)
                
                # Extract detailed listener information
                listener_details = []
                for listener in listeners:
                    listener_info = {
                        'protocol': listener.get('Protocol', 'Unknown'),
                        'port': listener.get('Port', 0),
                        'ssl_policy': listener.get('SslPolicy'),
                        'certificates': [cert.get('CertificateArn') for cert in listener.get('Certificates', [])],
                        'default_actions': listener.get('DefaultActions', [])
                    }
                    listener_details.append(listener_info)

                lb_info = {
                    'name': lb_name,
                    'arn': lb_arn,
                    'type': lb.get('Type', 'Unknown'),
                    'scheme': lb.get('Scheme', 'Unknown'),
                    'dns_name': lb.get('DNSName', 'Unknown'),
                    'canonical_hosted_zone_id': lb.get('CanonicalHostedZoneId', 'Unknown'),
                    'created_time': lb.get('CreatedTime').isoformat() if lb.get('CreatedTime') else None,
                    'state': lb.get('State', {}).get('Code', 'Unknown'),
                    'vpc_id': lb.get('VpcId', 'Unknown'),
                    'availability_zones': [az.get('ZoneName') for az in lb.get('AvailabilityZones', [])],
                    'security_groups': lb.get('SecurityGroups', []),
                    'ip_address_type': lb.get('IpAddressType', 'Unknown'),
                    'listeners': listener_details,
                    'listener_count': len(listeners),
                    'security_analysis': security_analysis
                }
                
                region_results['alb_nlbs'].append(lb_info)
                
                # Update counters
                if security_analysis['is_public']:
                    region_results['public_load_balancers'] += 1
                region_results['insecure_listeners'] += security_analysis['insecure_listeners']
                
                if security_analysis['severity'] == 'critical':
                    region_results['critical_findings'] += 1
                elif security_analysis['severity'] == 'warning':
                    region_results['warnings'] += 1
                    
        except ClientError as e:
            if e.response['Error']['Code'] not in ['UnauthorizedOperation', 'AccessDenied']:
                logger.warning(f"Error retrieving ALBs/NLBs in {region}: {e}")
                region_results['errors'].append(f"ALB/NLB error: {e.response['Error']['Message']}")
        
        # Calculate totals
        region_results['total_load_balancers'] = len(region_results['classic_elbs']) + len(region_results['alb_nlbs'])
        
        logger.info(f"Completed audit for {region}: {region_results['total_load_balancers']} load balancers found")
        return region_results
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code in ['UnauthorizedOperation', 'AccessDenied']:
            logger.warning(f"Access denied for region {region} - skipping")
        else:
            logger.error(f"Error in region {region}: {e.response['Error']['Message']}")
        return {
            'region': region,
            'classic_elbs': [],
            'alb_nlbs': [],
            'total_load_balancers': 0,
            'public_load_balancers': 0,
            'insecure_listeners': 0,
            'critical_findings': 0,
            'warnings': 0,
            'errors': [f"Region access error: {e.response['Error']['Message']}"]
        }

def audit_load_balancers_parallel(scan_all_regions_flag: bool, max_workers: int = 10) -> List[Dict]:
    """
    Audit load balancers across regions using parallel threading.
    """
    all_results = []
    
    if scan_all_regions_flag:
        logger.info("Auditing load balancers in all AWS regions in parallel...")
        regions = get_all_regions()
        # Limit concurrent threads to avoid overwhelming Lambda or hitting API limits
        max_workers = min(max_workers, len(regions))
    else:
        current_region = boto3.Session().region_name or 'us-east-1'
        logger.info(f"Auditing load balancers in current region: {current_region}")
        regions = [current_region]
        max_workers = 1
    
    logger.info(f"Using {max_workers} parallel workers for {len(regions)} regions")
    
    # Use ThreadPoolExecutor for better resource management
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all region audit tasks
        future_to_region = {
            executor.submit(audit_load_balancers_in_region, region, scan_all_regions_flag): region
            for region in regions
        }
        
        # Collect results as they complete
        for future in as_completed(future_to_region):
            region = future_to_region[future]
            try:
                result = future.result()
                all_results.append(result)
                logger.info(f"Completed audit for {region}: {result['total_load_balancers']} load balancers, "
                           f"{result['warnings']} warnings, {result['critical_findings']} critical")
            except Exception as e:
                logger.error(f"Error processing results for region {region}: {e}")
                all_results.append({
                    'region': region,
                    'classic_elbs': [],
                    'alb_nlbs': [],
                    'total_load_balancers': 0,
                    'public_load_balancers': 0,
                    'insecure_listeners': 0,
                    'critical_findings': 0,
                    'warnings': 0,
                    'errors': [f"Processing error: {str(e)}"]
                })
    
    logger.info("Parallel load balancer audit complete")
    return all_results

def calculate_summary_stats(results: List[Dict]) -> Dict:
    """Calculate summary statistics for the audit."""
    return {
        'total_regions_processed': len(results),
        'total_load_balancers': sum(r['total_load_balancers'] for r in results),
        'total_classic_elbs': sum(len(r['classic_elbs']) for r in results),
        'total_alb_nlbs': sum(len(r['alb_nlbs']) for r in results),
        'total_public_load_balancers': sum(r['public_load_balancers'] for r in results),
        'total_insecure_listeners': sum(r['insecure_listeners'] for r in results),
        'total_critical_findings': sum(r['critical_findings'] for r in results),
        'total_warnings': sum(r['warnings'] for r in results),
        'regions_with_errors': len([r for r in results if r['errors']]),
        'total_errors': sum(len(r['errors']) for r in results)
    }

def send_security_notifications(summary_stats: Dict, results: List[Dict], account_id: str) -> None:
    """Send SNS notifications for critical and high risk ELB/ALB security findings."""
    try:
        sns_client = boto3.client('sns')
        sns_topic_arn = os.environ.get('SNS_TOPIC_ARN')
        
        if not sns_topic_arn:
            logger.warning("SNS_TOPIC_ARN not configured, skipping notifications")
            return
        
        # Get current timestamp
        from datetime import datetime
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
        
        # Collect critical and high risk load balancers
        critical_load_balancers = []
        high_risk_load_balancers = []
        
        for region_result in results:
            # Check Classic ELBs
            for elb in region_result.get('classic_elbs', []):
                security_analysis = elb.get('security_analysis', {})
                if security_analysis.get('severity') == 'critical':
                    critical_load_balancers.append({
                        'name': elb['name'],
                        'type': 'Classic ELB',
                        'region': region_result['region'],
                        'scheme': elb['scheme'],
                        'dns_name': elb['dns_name'],
                        'findings': security_analysis.get('findings', []),
                        'is_public': security_analysis.get('is_public', False),
                        'insecure_listeners': security_analysis.get('insecure_listeners', 0)
                    })
                elif security_analysis.get('severity') == 'warning' and security_analysis.get('is_public'):
                    high_risk_load_balancers.append({
                        'name': elb['name'],
                        'type': 'Classic ELB',
                        'region': region_result['region'],
                        'scheme': elb['scheme'],
                        'dns_name': elb['dns_name'],
                        'findings': security_analysis.get('findings', []),
                        'is_public': security_analysis.get('is_public', False),
                        'insecure_listeners': security_analysis.get('insecure_listeners', 0)
                    })
            
            # Check ALBs/NLBs
            for lb in region_result.get('alb_nlbs', []):
                security_analysis = lb.get('security_analysis', {})
                if security_analysis.get('severity') == 'critical':
                    critical_load_balancers.append({
                        'name': lb['name'],
                        'type': lb['type'],
                        'region': region_result['region'],
                        'scheme': lb['scheme'],
                        'dns_name': lb['dns_name'],
                        'findings': security_analysis.get('findings', []),
                        'is_public': security_analysis.get('is_public', False),
                        'insecure_listeners': security_analysis.get('insecure_listeners', 0)
                    })
                elif security_analysis.get('severity') == 'warning' and security_analysis.get('is_public'):
                    high_risk_load_balancers.append({
                        'name': lb['name'],
                        'type': lb['type'],
                        'region': region_result['region'],
                        'scheme': lb['scheme'],
                        'dns_name': lb['dns_name'],
                        'findings': security_analysis.get('findings', []),
                        'is_public': security_analysis.get('is_public', False),
                        'insecure_listeners': security_analysis.get('insecure_listeners', 0)
                    })
        
        if not critical_load_balancers and not high_risk_load_balancers:
            logger.info("No critical or high risk ELB/ALB findings to notify")
            return
        
        # Build notification message
        subject = f"🚨 Load Balancer Security Alert - Account {account_id}"
        
        message_parts = [
            f"CRITICAL LOAD BALANCER SECURITY FINDINGS DETECTED",
            f"Account: {account_id}",
            f"Timestamp: {timestamp}",
            f"",
            f"SUMMARY:",
            f"• Total load balancers: {summary_stats['total_load_balancers']}",
            f"• Public load balancers: {summary_stats['total_public_load_balancers']}",
            f"• Critical findings: {summary_stats['total_critical_findings']}",
            f"• Warning findings: {summary_stats['total_warnings']}",
            f"• Insecure listeners: {summary_stats['total_insecure_listeners']}",
            f"• Regions processed: {summary_stats['total_regions_processed']}",
            f""
        ]
        
        # Add critical findings details
        if critical_load_balancers:
            message_parts.append("🔴 CRITICAL RISK LOAD BALANCERS:")
            for lb in critical_load_balancers:
                message_parts.append(f"  • {lb['name']} ({lb['type']}) - {lb['region']}")
                message_parts.append(f"    - Scheme: {lb['scheme']}")
                message_parts.append(f"    - DNS: {lb['dns_name']}")
                message_parts.append(f"    - Public access: {'YES' if lb['is_public'] else 'NO'}")
                message_parts.append(f"    - Insecure listeners: {lb['insecure_listeners']}")
                for finding in lb['findings']:
                    message_parts.append(f"    - 🚨 {finding}")
                message_parts.append(f"    - ⚠️  IMMEDIATE ACTION REQUIRED!")
            message_parts.append("")
        
        # Add high risk findings details
        if high_risk_load_balancers:
            message_parts.append("🟠 HIGH RISK LOAD BALANCERS (Public + Security Issues):")
            for lb in high_risk_load_balancers:
                message_parts.append(f"  • {lb['name']} ({lb['type']}) - {lb['region']}")
                message_parts.append(f"    - Scheme: {lb['scheme']}")
                message_parts.append(f"    - DNS: {lb['dns_name']}")
                message_parts.append(f"    - Public access: {'YES' if lb['is_public'] else 'NO'}")
                message_parts.append(f"    - Insecure listeners: {lb['insecure_listeners']}")
                for finding in lb['findings']:
                    message_parts.append(f"    - ⚠️  {finding}")
            message_parts.append("")
        
        # Add remediation recommendations
        message_parts.extend([
            "IMMEDIATE ACTIONS REQUIRED:",
            "1. Review and secure insecure HTTP listeners on public load balancers",
            "2. Implement SSL/TLS termination for all public-facing load balancers",
            "3. Update security groups to restrict unnecessary access",
            "4. Enable access logging for audit trails",
            "5. Consider using internal load balancers for internal traffic",
            "6. Implement Web Application Firewall (WAF) for ALBs",
            "",
            "REMEDIATION EXAMPLES:",
            "# Update ALB listener to use HTTPS",
            "aws elbv2 modify-listener --listener-arn arn:aws:... --protocol HTTPS --port 443",
            "",
            "# Add SSL certificate to load balancer",
            "aws elbv2 modify-listener --listener-arn arn:aws:... --certificates CertificateArn=arn:aws:acm:...",
            "",
            "For detailed load balancer analysis, check CloudWatch logs or run the audit manually.",
            "",
            "This alert was generated by the automated ELB/ALB Security Audit Lambda function."
        ])
        
        message = "\n".join(message_parts)
        
        # Send SNS notification
        response = sns_client.publish(
            TopicArn=sns_topic_arn,
            Subject=subject,
            Message=message
        )
        
        message_id = response.get('MessageId', 'Unknown')
        logger.info(f"SNS notification sent successfully. MessageId: {message_id}")
        logger.info(f"Notified about {len(critical_load_balancers)} critical and {len(high_risk_load_balancers)} high risk load balancers")
        
    except Exception as e:
        logger.error(f"Failed to send SNS notification: {str(e)}")
        # Don't raise exception to avoid failing the main audit process

def lambda_handler(event: Dict[str, Any], context) -> Dict[str, Any]:
    """
    AWS Lambda handler for ELB/ALB security audit
    
    Args:
        event: Lambda event object
        context: Lambda context object
        
    Returns:
        Dict with audit results
    """
    try:
        logger.info("Starting ELB/ALB security audit")
        
        # Extract parameters from event or environment variables
        params = event.get('params', {})
        scan_all_regions_flag = params.get('scan_all_regions',
                                         os.environ.get('SCAN_ALL_REGIONS', 'false').lower() == 'true')
        max_workers = params.get('max_workers', int(os.environ.get('MAX_WORKERS', '10')))
        
        logger.info(f"Configuration - Scan all regions: {scan_all_regions_flag}, Max workers: {max_workers}")
        
        # Validate credentials
        try:
            sts_client = boto3.client('sts')
            response = sts_client.get_caller_identity()
            account_id = response.get('Account', 'Unknown')
            caller_arn = response.get('Arn', 'Unknown')
            logger.info(f"Auditing load balancers in AWS Account: {account_id}")
        except Exception as e:
            logger.error(f"Failed to validate credentials: {e}")
            raise Exception("Invalid AWS credentials")
        
        # Perform audit using parallel processing
        results = audit_load_balancers_parallel(scan_all_regions_flag, max_workers)
        
        # Calculate summary statistics
        summary_stats = calculate_summary_stats(results)
        
        # Determine if alerts should be triggered
        alerts_triggered = (summary_stats['total_critical_findings'] > 0 or 
                          summary_stats['total_public_load_balancers'] > 0 or
                          summary_stats['total_errors'] > 0)
        status_code = 201 if alerts_triggered else 200
        
        # Log summary
        logger.info(f"Audit completed. "
                   f"Regions processed: {summary_stats['total_regions_processed']}, "
                   f"Load balancers found: {summary_stats['total_load_balancers']}, "
                   f"Public load balancers: {summary_stats['total_public_load_balancers']}, "
                   f"Warnings: {summary_stats['total_warnings']}")
        
        if alerts_triggered:
            # Send SNS notifications for critical and high risk findings
            send_security_notifications(summary_stats, results, account_id)
            logger.warning(f"SECURITY ALERT: {summary_stats['total_critical_findings']} critical findings, "
                         f"{summary_stats['total_public_load_balancers']} public load balancers detected!")
        
        if summary_stats['total_load_balancers'] == 0:
            logger.info("No load balancers found in scanned regions")
        
        # Extract detailed findings for easy consumption
        detailed_findings = {
            'public_load_balancers': [],
            'insecure_load_balancers': [],
            'critical_ssl_issues': [],
            'all_load_balancers': []
        }
        
        for region_result in results:
            # Process Classic ELBs
            for elb in region_result.get('classic_elbs', []):
                lb_summary = {
                    'name': elb['name'],
                    'type': 'Classic ELB',
                    'region': region_result['region'],
                    'dns_name': elb['dns_name'],
                    'scheme': elb['scheme'],
                    'is_public': elb['security_analysis']['is_public'],
                    'insecure_listeners': elb['security_analysis']['insecure_listeners'],
                    'severity': elb['security_analysis']['severity']
                }
                detailed_findings['all_load_balancers'].append(lb_summary)
                
                if lb_summary['is_public']:
                    detailed_findings['public_load_balancers'].append(lb_summary)
                if lb_summary['insecure_listeners'] > 0:
                    detailed_findings['insecure_load_balancers'].append(lb_summary)
                if lb_summary['severity'] == 'critical':
                    detailed_findings['critical_ssl_issues'].append(lb_summary)
            
            # Process ALBs/NLBs
            for lb in region_result.get('alb_nlbs', []):
                lb_summary = {
                    'name': lb['name'],
                    'type': lb['type'],
                    'region': region_result['region'],
                    'dns_name': lb['dns_name'],
                    'scheme': lb['scheme'],
                    'is_public': lb['security_analysis']['is_public'],
                    'insecure_listeners': lb['security_analysis']['insecure_listeners'],
                    'severity': lb['security_analysis']['severity']
                }
                detailed_findings['all_load_balancers'].append(lb_summary)
                
                if lb_summary['is_public']:
                    detailed_findings['public_load_balancers'].append(lb_summary)
                if lb_summary['insecure_listeners'] > 0:
                    detailed_findings['insecure_load_balancers'].append(lb_summary)
                if lb_summary['severity'] == 'critical':
                    detailed_findings['critical_ssl_issues'].append(lb_summary)

        return {
            'statusCode': status_code,
            'body': {
                'message': f'ELB/ALB security audit completed successfully',
                'results': {
                    'region_results': results,
                    'summary': summary_stats,
                    'detailed_findings': detailed_findings,
                    'audit_parameters': {
                        'scan_all_regions': scan_all_regions_flag,
                        'max_workers': max_workers,
                        'account_id': account_id,
                        'caller_arn': caller_arn,
                        'timestamp': datetime.now().isoformat()
                    }
                },
                'executionId': context.aws_request_id,
                'alerts_triggered': alerts_triggered
            }
        }
        
    except Exception as e:
        logger.error(f"ELB/ALB security audit failed: {str(e)}")
        return {
            'statusCode': 500,
            'body': {
                'error': str(e),
                'message': 'ELB/ALB security audit failed',
                'executionId': context.aws_request_id
            }
        }