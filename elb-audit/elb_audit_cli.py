#!/usr/bin/env python3
"""
Waaaw ELB/ALB Auditor & Security Scanner
- Lists ELBs and ALBs with listeners and targets
- Detects public exposure and insecure protocols
- Shows target health
"""

import boto3
import argparse
import sys
import threading
import ssl
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError, ProfileNotFound
from typing import List, Dict, Optional, Tuple

# ANSI colors for terminal output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RESET = '\033[0m'

# Comprehensive list of AWS regions as of 2024
# This list can be maintained and updated as AWS adds new regions
AWS_REGIONS = [
    # US East (N. Virginia, Ohio)
    'us-east-1',
    'us-east-2',
    
    # US West (N. California, Oregon)
    'us-west-1',
    'us-west-2',
    
    # Africa (Cape Town)
    'af-south-1',
    
    # Asia Pacific (Hong Kong, Hyderabad, Jakarta, Melbourne, Mumbai, Osaka, Seoul, Singapore, Sydney, Tokyo)
    'ap-east-1',
    'ap-south-1',
    'ap-south-2',
    'ap-southeast-1',
    'ap-southeast-2',
    'ap-southeast-3',
    'ap-southeast-4',
    'ap-northeast-1',
    'ap-northeast-2',
    'ap-northeast-3',
    
    # Canada (Central)
    'ca-central-1',
    'ca-west-1',
    
    # Europe (Frankfurt, Ireland, London, Milan, Paris, Spain, Stockholm, Zurich)
    'eu-central-1',
    'eu-central-2',
    'eu-west-1',
    'eu-west-2',
    'eu-west-3',
    'eu-south-1',
    'eu-south-2',
    'eu-north-1',
    
    # Middle East (Bahrain, UAE)
    'me-south-1',
    'me-central-1',
    
    # South America (São Paulo)
    'sa-east-1',
    
    # Israel (Tel Aviv)
    'il-central-1',
]

def color_text(text, color):
    if sys.stdout.isatty():
        return f"{color}{text}{Colors.RESET}"
    return text

def is_public(elb):
    return elb.get('Scheme', '') == 'internet-facing'

def print_header(title):
    print("\n" + "="*len(title))
    print(title)
    print("="*len(title))

def validate_aws_credentials(session=None):
    """Validate AWS credentials before proceeding."""
    try:
        if session:
            sts = session.client('sts')
        else:
            sts = boto3.client('sts')
        
        response = sts.get_caller_identity()
        print(f"Using AWS Account: {response.get('Account', 'Unknown')}")
        print(f"User/Role: {response.get('Arn', 'Unknown')}")
        return True
    except (NoCredentialsError, PartialCredentialsError) as e:
        print(f"Error: AWS credentials not found or incomplete: {e}")
        print("Please configure your credentials using 'aws configure' or environment variables.")
        return False
    except ClientError as e:
        print(f"Error validating credentials: {e.response['Error']['Message']}")
        return False

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
            'domain_name': domain_name,
            'status': cert.get('Status', 'Unknown'),
            'key_algorithm': key_algorithm,
            'san_count': san_count,
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
                                'severity': 'CRITICAL',
                                'issue': 'No supported TLS versions detected',
                                'hostname': hostname,
                                'port': port
                            })
                            
                    except Exception as e:
                        ssl_issues.append({
                            'severity': 'MEDIUM',
                            'issue': f'TLS analysis failed: {str(e)}',
                            'hostname': hostname,
                            'port': port
                        })
                
                # Check SSL policy (ALB specific)
                ssl_policy = listener.get('SslPolicy')
                if ssl_policy:
                    # Check for weak SSL policies
                    weak_policies = [
                        'ELBSecurityPolicy-2016-08',
                        'ELBSecurityPolicy-TLS-1-0-2015-04',
                        'ELBSecurityPolicy-TLS-1-1-2017-01'
                    ]
                    
                    if ssl_policy in weak_policies:
                        ssl_issues.append({
                            'severity': 'HIGH',
                            'issue': f'Weak SSL policy: {ssl_policy}',
                            'hostname': hostname,
                            'port': port,
                            'recommendation': 'Use ELBSecurityPolicy-TLS-1-2-2017-01 or newer'
                        })
                
    except Exception as e:
        ssl_issues.append({
            'severity': 'MEDIUM',
            'issue': f'SSL configuration analysis failed: {str(e)}',
            'hostname': hostname if 'hostname' in locals() else 'Unknown'
        })
    
    return ssl_issues

def get_available_regions(ec2_client):
    """Get list of available AWS regions."""
    try:
        response = ec2_client.describe_regions()
        return [region['RegionName'] for region in response['Regions']]
    except ClientError as e:
        print(f"Warning: Could not get regions list: {e.response['Error']['Message']}")
        print("Using predefined comprehensive list of AWS regions.")
        # Return comprehensive list as fallback
        return AWS_REGIONS

def audit_region_parallel(region: str, session=None) -> dict:
    """Audit load balancers in a single region (for parallel processing)."""
    print_lock = threading.Lock()
    
    try:
        with print_lock:
            print(f"🔍 Scanning region: {region}")
        
        # Create clients for this region
        if session:
            elb_client = session.client('elb', region_name=region)
            elbv2_client = session.client('elbv2', region_name=region)
        else:
            elb_client = boto3.client('elb', region_name=region)
            elbv2_client = boto3.client('elbv2', region_name=region)
        
        region_results = {
            'region': region,
            'classic_elbs': [],
            'alb_nlbs': [],
            'public_elbs': 0,
            'insecure_listeners': 0,
            'errors': []
        }
        
        # Audit Classic ELBs
        try:
            classic_response = elb_client.describe_load_balancers()
            classic_elbs = classic_response.get('LoadBalancerDescriptions', [])
            
            for elb in classic_elbs:
                elb_info = {
                    'name': elb['LoadBalancerName'],
                    'scheme': elb['Scheme'],
                    'dns_name': elb.get('DNSName', 'Unknown'),
                    'listeners': [],
                    'is_public': is_public(elb),
                    'insecure_listeners': []
                }
                
                if elb_info['is_public']:
                    region_results['public_elbs'] += 1
                
                # Check for insecure listeners
                for listener_desc in elb.get('ListenerDescriptions', []):
                    listener = listener_desc.get('Listener', {})
                    protocol = listener.get('Protocol', '').upper()
                    port = listener.get('LoadBalancerPort', 0)
                    instance_port = listener.get('InstancePort', 0)
                    
                    listener_info = {
                        'protocol': protocol,
                        'port': port,
                        'instance_port': instance_port,
                        'insecure': False
                    }
                    
                    if protocol == 'HTTP' or (port in [80, 8080, 8000, 3000] and protocol != 'HTTPS'):
                        region_results['insecure_listeners'] += 1
                        listener_info['insecure'] = True
                        elb_info['insecure_listeners'].append(f"{protocol}:{port}")
                    
                    elb_info['listeners'].append(listener_info)
                
                region_results['classic_elbs'].append(elb_info)
                        
        except ClientError as e:
            if e.response['Error']['Code'] not in ['UnauthorizedOperation', 'AccessDenied']:
                region_results['errors'].append(f"Classic ELB error: {e.response['Error']['Message']}")
        
        # Audit ALBs/NLBs
        try:
            alb_response = elbv2_client.describe_load_balancers()
            alb_nlbs = alb_response.get('LoadBalancers', [])
            
            for lb in alb_nlbs:
                lb_info = {
                    'name': lb['LoadBalancerName'],
                    'type': lb['Type'],
                    'scheme': lb['Scheme'],
                    'dns_name': lb.get('DNSName', 'Unknown'),
                    'state': lb.get('State', {}).get('Code', 'Unknown'),
                    'listeners': [],
                    'is_public': is_public(lb),
                    'insecure_listeners': []
                }
                
                if lb_info['is_public']:
                    region_results['public_elbs'] += 1
                
                # Get listeners and check for insecure ones
                try:
                    listeners_response = elbv2_client.describe_listeners(LoadBalancerArn=lb.get('LoadBalancerArn'))
                    listeners = listeners_response.get('Listeners', [])
                    
                    for listener in listeners:
                        protocol = listener.get('Protocol', '').upper()
                        port = listener.get('Port', 0)
                        
                        listener_info = {
                            'protocol': protocol,
                            'port': port,
                            'insecure': False
                        }
                        
                        if protocol == 'HTTP' or (port in [80, 8080, 8000, 3000] and protocol != 'HTTPS'):
                            region_results['insecure_listeners'] += 1
                            listener_info['insecure'] = True
                            lb_info['insecure_listeners'].append(f"{protocol}:{port}")
                        
                        lb_info['listeners'].append(listener_info)
                            
                except ClientError:
                    pass  # Skip individual listener errors
                
                region_results['alb_nlbs'].append(lb_info)
                    
        except ClientError as e:
            if e.response['Error']['Code'] not in ['UnauthorizedOperation', 'AccessDenied']:
                region_results['errors'].append(f"ALB/NLB error: {e.response['Error']['Message']}")
        
        total_lbs = len(region_results['classic_elbs']) + len(region_results['alb_nlbs'])
        
        with print_lock:
            if total_lbs > 0:
                print(f"  ✅ Found {total_lbs} load balancers in {region}")
                if region_results['public_elbs'] > 0:
                    print(f"  ⚠️  {region_results['public_elbs']} public load balancers")
                if region_results['insecure_listeners'] > 0:
                    print(f"  🚨 {region_results['insecure_listeners']} insecure listeners")
            else:
                print(f"  ✅ No load balancers found in {region}")
        
        return region_results
        
    except ClientError as e:
        error_msg = f"Error scanning {region}: {e.response['Error']['Message']}"
        with print_lock:
            print(f"  ❌ {error_msg}")
        return {
            'region': region,
            'classic_elbs': [],
            'alb_nlbs': [],
            'public_elbs': 0,
            'insecure_listeners': 0,
            'errors': [error_msg]
        }

def audit_regions_parallel(regions: list, max_workers: int = 5, session=None) -> list:
    """Parallel region auditing for CLI."""
    print(f"🚀 Using parallel processing with {max_workers} workers for better performance...")
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_region = {
            executor.submit(audit_region_parallel, region, session): region
            for region in regions
        }
        
        all_results = []
        for future in as_completed(future_to_region):
            region = future_to_region[future]
            try:
                result = future.result()
                all_results.append(result)
            except Exception as e:
                print(f"❌ Error processing region {region}: {e}")
                all_results.append({
                    'region': region,
                    'classic_elbs': 0,
                    'alb_nlbs': 0,
                    'public_elbs': 0,
                    'insecure_listeners': 0,
                    'errors': [f"Processing error: {str(e)}"]
                })
        
        return all_results

def display_detailed_findings(results: list):
    """Display detailed findings from parallel audit results."""
    print("\n" + "="*60)
    print("DETAILED FINDINGS")
    print("="*60)
    
    for region_result in results:
        region = region_result['region']
        classic_elbs = region_result.get('classic_elbs', [])
        alb_nlbs = region_result.get('alb_nlbs', [])
        
        if not classic_elbs and not alb_nlbs:
            continue
            
        print_header(f"Load Balancers in {region}")
        
        # Display Classic ELBs
        if classic_elbs:
            print(f"\nClassic ELBs ({len(classic_elbs)} found):")
            for elb in classic_elbs:
                name = elb['name']
                scheme = elb['scheme']
                dns_name = elb['dns_name']
                
                scheme_color = Colors.GREEN if scheme != 'internet-facing' else Colors.RED
                scheme_text = color_text(scheme, scheme_color)
                
                print(f"\n  Load Balancer: {name} ({scheme_text})")
                print(f"  DNS Name: {dns_name}")
                print("  Listeners:")
                
                insecure_found = False
                for listener in elb['listeners']:
                    proto = listener['protocol']
                    port = listener['port']
                    instance_port = listener['instance_port']
                    line = f"   - {proto} {port} -> instance {instance_port}"
                    
                    if listener['insecure']:
                        line = color_text(line + " ⚠️ Insecure", Colors.YELLOW)
                        insecure_found = True
                    print(line)
                
                if elb['is_public']:
                    print(color_text("  ⚠️ Publicly accessible ELB detected!", Colors.RED))
                if elb['insecure_listeners']:
                    print(color_text(f"  🚨 Insecure listeners: {', '.join(elb['insecure_listeners'])}", Colors.YELLOW))
                if not insecure_found and not elb['is_public']:
                    print(color_text("  ✅ No security issues detected on this ELB.", Colors.GREEN))
        
        # Display ALBs/NLBs
        if alb_nlbs:
            print(f"\nApplication/Network Load Balancers ({len(alb_nlbs)} found):")
            for lb in alb_nlbs:
                name = lb['name']
                lb_type = lb['type']
                scheme = lb['scheme']
                dns_name = lb['dns_name']
                state = lb['state']
                
                scheme_color = Colors.GREEN if scheme != 'internet-facing' else Colors.RED
                scheme_text = color_text(scheme, scheme_color)
                
                print(f"\n  Load Balancer: {name} (Type: {lb_type}, Scheme: {scheme_text})")
                print(f"  DNS Name: {dns_name}")
                print(f"  State: {state}")
                print("  Listeners:")
                
                insecure_found = False
                for listener in lb['listeners']:
                    proto = listener['protocol']
                    port = listener['port']
                    line = f"   - {proto} port {port}"
                    
                    if listener['insecure']:
                        line = color_text(line + " ⚠️ Insecure", Colors.YELLOW)
                        insecure_found = True
                    print(line)
                
                if lb['is_public']:
                    print(color_text("  ⚠️ Publicly accessible ALB/NLB detected!", Colors.RED))
                if lb['insecure_listeners']:
                    print(color_text(f"  🚨 Insecure listeners: {', '.join(lb['insecure_listeners'])}", Colors.YELLOW))
                if not insecure_found and not lb['is_public']:
                    print(color_text("  ✅ No security issues detected on this ALB/NLB.", Colors.GREEN))

def send_sns_alert(summary_stats: dict, sns_topic_arn: str, account_id: str = "Unknown", session=None):
    """Send SNS alert for load balancer security findings."""
    if not sns_topic_arn:
        return
    
    try:
        # Create SNS client
        if session:
            sns_client = session.client('sns')
        else:
            sns_client = boto3.client('sns')
        
        # Build message
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
        
        subject = f"🚨 Load Balancer Security Alert - Account {account_id}"
        
        message_parts = [
            f"LOAD BALANCER SECURITY FINDINGS DETECTED",
            f"Account: {account_id}",
            f"Timestamp: {timestamp}",
            f"",
            f"SUMMARY:",
            f"• Total load balancers: {summary_stats['total_load_balancers']}",
            f"• Public load balancers: {summary_stats['total_public_elbs']}",
            f"• Insecure listeners: {summary_stats['total_insecure_listeners']}",
            f"• Regions processed: {summary_stats['regions_processed']}",
            f"",
            f"IMMEDIATE ACTIONS REQUIRED:",
            f"1. Review and secure insecure HTTP listeners on public load balancers",
            f"2. Implement SSL/TLS termination for all public-facing load balancers",
            f"3. Update security groups to restrict unnecessary access",
            f"4. Enable access logging for audit trails",
            f"",
            f"This alert was generated by the ELB/ALB Security Audit CLI tool."
        ]
        
        message = "\\n".join(message_parts)
        
        # Send SNS notification
        response = sns_client.publish(
            TopicArn=sns_topic_arn,
            Subject=subject,
            Message=message
        )
        
        message_id = response.get('MessageId', 'Unknown')
        print(f"📧 SNS alert sent successfully. MessageId: {message_id}")
        print(f"   Topic: {sns_topic_arn}")
        
    except Exception as e:
        print(f"{Colors.RED}❌ Failed to send SNS alert: {str(e)}{Colors.RESET}")
        print(f"   Topic ARN: {sns_topic_arn}")

def audit_classic_elbs(elb_client, region=None):
    if region:
        print_header(f"Classic ELBs in {region}")
    else:
        print_header("Classic ELBs")

    try:
        elbs = elb_client.describe_load_balancers()['LoadBalancerDescriptions']
        if not elbs:
            print("No Classic ELBs found.")
            return

        for elb in elbs:
            name = elb['LoadBalancerName']
            public = is_public(elb)
            scheme_color = Colors.GREEN if not public else Colors.RED
            scheme_text = color_text(elb['Scheme'], scheme_color)

            print(f"\nLoad Balancer: {name} ({scheme_text})")
            print("Listeners:")

            insecure_found = False
            for listener in elb['ListenerDescriptions']:
                proto = listener['Listener']['Protocol']
                port = listener['Listener']['LoadBalancerPort']
                instance_port = listener['Listener']['InstancePort']
                insecure = (proto.upper() == 'HTTP' and port == 80)
                line = f" - {proto} {port} -> instance {instance_port}"
                if insecure:
                    line = color_text(line + " ⚠️ Insecure (HTTP on port 80)", Colors.YELLOW)
                    insecure_found = True
                print(line)

            if public:
                print(color_text("⚠️ Publicly accessible ELB detected!", Colors.RED))
            if not insecure_found and not public:
                print(color_text("✅ No security issues detected on this ELB.", Colors.GREEN))
    except ClientError as e:
        if e.response['Error']['Code'] in ['UnauthorizedOperation', 'AccessDenied']:
            print(f"Access denied for Classic ELBs in {region if region else 'current region'}")
        else:
            print(f"Error accessing Classic ELBs: {e.response['Error']['Message']}")

def audit_albs(elbv2_client, region=None):
    if region:
        print_header(f"Application/Network Load Balancers (ALB/NLB) in {region}")
    else:
        print_header("Application/Network Load Balancers (ALB/NLB)")

    try:
        lbs = elbv2_client.describe_load_balancers()['LoadBalancers']
        if not lbs:
            print("No ALBs/NLBs found.")
            return

        for lb in lbs:
            lb_arn = lb['LoadBalancerArn']
            name = lb['LoadBalancerName']
            lb_type = lb['Type']
            scheme = lb['Scheme']
            public = scheme == 'internet-facing'

            scheme_color = Colors.GREEN if not public else Colors.RED
            scheme_text = color_text(scheme, scheme_color)

            print(f"\nLoad Balancer: {name} (Type: {lb_type}, Scheme: {scheme_text})")

            # List listeners
            listeners = elbv2_client.describe_listeners(LoadBalancerArn=lb_arn)['Listeners']
            insecure_found = False
            for listener in listeners:
                proto = listener['Protocol']
                port = listener['Port']
                line = f" - {proto} port {port}"

                if proto.upper() == 'HTTP' and port == 80:
                    line = color_text(line + " ⚠️ Insecure listener (HTTP)", Colors.YELLOW)
                    insecure_found = True
                print(line)

                # List target groups & target health
                rules = elbv2_client.describe_rules(ListenerArn=listener['ListenerArn'])['Rules']
                target_groups = set()
                for rule in rules:
                    for action in rule.get('Actions', []):
                        if action.get('Type') == 'forward' and 'TargetGroupArn' in action:
                            target_groups.add(action['TargetGroupArn'])

                if not target_groups:
                    print("   No target groups found.")
                else:
                    for tg_arn in target_groups:
                        tg = elbv2_client.describe_target_groups(TargetGroupArns=[tg_arn])['TargetGroups'][0]
                        tg_name = tg['TargetGroupName']
                        tg_proto = tg['Protocol']
                        tg_port = tg['Port']
                        print(f"   Target Group: {tg_name} ({tg_proto}:{tg_port})")

                        # Target health
                        healths = elbv2_client.describe_target_health(TargetGroupArn=tg_arn)['TargetHealthDescriptions']
                        for h in healths:
                            target_id = h['Target']['Id']
                            state = h['TargetHealth']['State']
                            healthy = state == 'healthy'
                            state_text = color_text(state, Colors.GREEN if healthy else Colors.RED)
                            print(f"     - Target: {target_id}, Health: {state_text}")

            if public:
                print(color_text("⚠️ Publicly accessible ALB/NLB detected!", Colors.RED))
            if not insecure_found and not public:
                print(color_text("✅ No security issues detected on this ALB/NLB.", Colors.GREEN))
    except ClientError as e:
        if e.response['Error']['Code'] in ['UnauthorizedOperation', 'AccessDenied']:
            print(f"Access denied for ALBs/NLBs in {region if region else 'current region'}")
        else:
            print(f"Error accessing ALBs/NLBs: {e.response['Error']['Message']}")

def audit_region(region, session=None):
    """Audit ELBs and ALBs in a specific region."""
    try:
        if session:
            elb_client = session.client('elb', region_name=region)
            elbv2_client = session.client('elbv2', region_name=region)
        else:
            elb_client = boto3.client('elb', region_name=region)
            elbv2_client = boto3.client('elbv2', region_name=region)
        
        audit_classic_elbs(elb_client, region)
        audit_albs(elbv2_client, region)
        
    except ClientError as e:
        if e.response['Error']['Code'] in ['UnauthorizedOperation', 'AccessDenied']:
            print(f"\nAccess denied for region {region} - skipping")
        else:
            print(f"\nError accessing region {region}: {e.response['Error']['Message']}")

def main():
    parser = argparse.ArgumentParser(
        description="Comprehensive ELB/ALB Security Auditor with multi-region support",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
  # Basic audit in specific region
  ./elb_audit.py --region us-east-1
  
  # Fast multi-region audit with parallel processing
  ./elb_audit.py --all-regions --max-workers 10
  
  # Production audit with SNS alerts and optimized performance
  ./elb_audit.py --profile production --all-regions --sns-topic arn:aws:sns:us-east-1:123456789012:elb-alerts --max-workers 15
  
  # Sequential scan if needed (disable parallel processing)
  ./elb_audit.py --all-regions --no-parallel

SECURITY CHECKS:
- Public vs internal load balancers
- Insecure HTTP listeners
- SSL/TLS certificate analysis (Lambda version)
- Target health status  
- Classic ELB and modern ALB/NLB support
- Parallel processing for faster multi-region scans
"""
    )
    parser.add_argument('--region', help='Specific AWS region to audit')
    parser.add_argument('--all-regions', action='store_true', 
                       help='Audit all available AWS regions')
    parser.add_argument('--profile', help='AWS profile to use')
    parser.add_argument('--sns-topic', type=str,
                       help='SNS topic ARN for sending alerts (optional - if not provided, no SNS alerts will be sent)')
    parser.add_argument('--no-parallel', action='store_true',
                       help='Disable parallel processing and scan regions sequentially')
    parser.add_argument('--max-workers', type=int, default=5,
                       help='Maximum number of worker threads for parallel processing (default: 5, max: 20)')
    
    args = parser.parse_args()

    # Validate arguments
    if not args.region and not args.all_regions:
        parser.error("Must specify either --region or --all-regions")
    
    # Validate max_workers
    if args.max_workers < 1:
        args.max_workers = 1
    elif args.max_workers > 20:
        args.max_workers = 20

    # Create AWS session with profile if specified
    session = None
    if args.profile:
        try:
            session = boto3.Session(profile_name=args.profile)
            print(f"Using AWS profile: {args.profile}")
        except ProfileNotFound:
            print(f"Error: AWS profile '{args.profile}' not found.")
            print("Available profiles can be listed with: aws configure list-profiles")
            sys.exit(1)
        except Exception as e:
            print(f"Error loading AWS profile '{args.profile}': {e}")
            sys.exit(1)

    # Validate credentials
    if not validate_aws_credentials(session):
        sys.exit(1)

    print("=" * 60)
    print("ELB/ALB SECURITY AUDIT")
    print("=" * 60)

    if args.all_regions:
        # Get all available regions
        ec2_client = session.client('ec2') if session else boto3.client('ec2')
        regions = get_available_regions(ec2_client)
        print(f"Auditing {len(regions)} regions...")
        
        # Use parallel processing for multiple regions
        use_parallel = not args.no_parallel and len(regions) > 1
        
        if use_parallel:
            print(f"🚀 Using parallel processing with {args.max_workers} workers for better performance...")
            results = audit_regions_parallel(regions, args.max_workers, session)
            
            # Calculate summary statistics
            summary_stats = {
                'total_load_balancers': sum(len(r['classic_elbs']) + len(r['alb_nlbs']) for r in results),
                'total_public_elbs': sum(r['public_elbs'] for r in results),
                'total_insecure_listeners': sum(r['insecure_listeners'] for r in results),
                'regions_processed': len(results),
                'regions_with_errors': len([r for r in results if r['errors']])
            }
            
            # Print summary
            print(f"\n📊 PARALLEL SCAN SUMMARY:")
            print(f"   Regions processed: {summary_stats['regions_processed']}")
            print(f"   Total load balancers: {summary_stats['total_load_balancers']}")
            print(f"   Public load balancers: {summary_stats['total_public_elbs']}")
            print(f"   Insecure listeners: {summary_stats['total_insecure_listeners']}")
            if summary_stats['regions_with_errors'] > 0:
                print(f"   Regions with errors: {summary_stats['regions_with_errors']}")
            
            # Display detailed findings
            display_detailed_findings(results)
            
            # Send SNS alert if configured and findings exist
            if args.sns_topic and (summary_stats['total_public_elbs'] > 0 or summary_stats['total_insecure_listeners'] > 0):
                try:
                    # Get account ID
                    if session:
                        sts = session.client('sts')
                    else:
                        sts = boto3.client('sts')
                    account_id = sts.get_caller_identity().get('Account', 'Unknown')
                    
                    print(f"\n📧 Sending SNS alert to: {args.sns_topic}")
                    send_sns_alert(summary_stats, args.sns_topic, account_id, session)
                except Exception as e:
                    print(f"{Colors.RED}❌ Failed to send SNS alert: {str(e)}{Colors.RESET}")
            elif args.sns_topic:
                print(f"\n📧 No SNS alert sent - no security findings detected")
        else:
            print("Using sequential processing...")
            for region in regions:
                audit_region(region, session)
    else:
        # Audit specific region
        audit_region(args.region, session)

    print("\n" + "=" * 60)
    print("AUDIT COMPLETE")
    print("=" * 60)

if __name__ == "__main__":
    main()

