# 🛠️ AWS Helper Scripts Collection

A comprehensive collection of AWS DevOps and security scripts designed to streamline cloud operations, enhance security posture, and automate common tasks across AWS environments.

## 🌟 Features

- **AWS Security & Compliance Tools** - Monitor and audit your AWS infrastructure
- **Security Analysis Scripts** - Identify vulnerabilities and compliance gaps
- **Cost Optimization Tools** - Track and optimize AWS cloud spending
- **Resource Inventory Tools** - Comprehensive AWS resource discovery and reporting
- **Automation Ready** - All scripts designed for integration into CI/CD pipelines

## 📁 Script Categories

### 🔐 AWS Security & Compliance

| Script | Description | Key Features |
|--------|-------------|--------------|
| [**IAM MFA Checker**](check-iam-users-no-mfa/) | Identifies IAM users without MFA enabled | Console access audit, compliance reporting, [Lambda version](check-iam-users-no-mfa-lambda/) |
| [**Public RDS Detector**](check-public-rds/) | Finds publicly accessible RDS instances | Multi-region scan, security assessment, [Lambda version](check-public-rds-lambda/) |
| [**Public S3 Bucket Scanner**](check-public-s3/) | Lists publicly accessible S3 buckets | Bucket policy analysis, exposure detection, [Lambda version](check-public-s3-lambda/) |
| [**Security Group Auditor**](find-unused-sgs/) | Identifies unused security groups | Resource optimization, cleanup automation, [Lambda version](find-unused-sgs-lambda/) |
| [**ELB Security Auditor**](elb-audit/) | Comprehensive load balancer security audit | SSL/TLS analysis, listener configuration, [Lambda version](elb-audit-lambda/) |

### 💰 AWS Cost Management

| Script | Description | Key Features |
|--------|-------------|--------------|
| [**AWS Cost Monitor**](aws-cost-monitor/) | Real-time cost tracking and alerting | Threshold monitoring, spend analysis, [Lambda version](aws-cost-monitor-lambda/) |
| [**EBS Snapshot Cleanup**](cleanup-snapshots/) | Automated cleanup of old snapshots | Age-based retention, cost savings, [Lambda version](cleanup-snapshots-lambda/) |
| [**Idle EC2 Manager**](stop-idle-ec2/) | Stops underutilized EC2 instances | CPU monitoring, automated shutdown, [Lambda version](stop-idle-ec2-lambda/) |

### 📊 AWS Resource Inventory

| Script | Description | Key Features |
|--------|-------------|--------------|
| [**Lambda Function Lister**](list-lambdas/) | Comprehensive Lambda inventory | Runtime analysis, configuration audit, [Lambda version](list-lambdas-lambda/) |
| [**RDS Instance Reporter**](list-rds-instances/) | Detailed RDS configuration reporting | Performance insights, security config, [Lambda version](list-rds-instances-lambda/) |
| [**ELB/ALB Inventory**](list-elbs-and-albs/) | Load balancer configuration audit | Health checks, target analysis, [Lambda version](list-elbs-and-albs-lambda/) |
| [**KMS Key Usage Tracker**](list-kms-keys-with-usage/) | KMS key utilization analysis | Usage tracking, cost optimization, [Lambda version](list-kms-keys-with-usage-lambda/) |
| [**Route53 Zone Analyzer**](list-route53-zones-and-records/) | DNS configuration audit | Record validation, health checks, [Lambda version](list-route53-zones-and-records-lambda/) |

### 🔍 AWS Runtime & Compliance

| Script | Description | Key Features |
|--------|-------------|--------------|
| [**Lambda Runtime Detector**](aws-deprecated-lambdas-runtime/) | Identifies deprecated Lambda runtimes | Multi-region scan, upgrade recommendations, [Lambda version](aws-deprecated-lambdas-runtime-lambda/) |


## 🚀 Quick Start

### Prerequisites

```bash
# For AWS scripts
pip install boto3 awscli
aws configure

# For Lambda deployments (required for all *-lambda folders)
# Install AWS SAM CLI
pip install aws-sam-cli
# OR using Homebrew on macOS
brew install aws-sam-cli
# OR download from: https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/install-sam-cli.html
```

### SNS Topics Setup (Required for Lambda Notifications)

Many Lambda scripts in this collection send notifications via SNS. Create the required SNS topics first:

```bash
# Deploy SNS topics using CloudFormation
aws cloudformation deploy \
  --template-file sns-topics.yaml \
  --stack-name aws-helper-scripts-sns-topics \
  --region us-east-1

# Get the topic ARNs for your Lambda environment variables
aws cloudformation describe-stacks \
  --stack-name aws-helper-scripts-sns-topics \
  --query 'Stacks[0].Outputs'
```

This creates two SNS topics:
- **SecurityFindings**: For security-related alerts (IAM, S3, RDS, etc.)
- **FinOps**: For cost management and optimization alerts

**Configure your Lambda functions** with these environment variables:
- `SNS_TOPIC_ARN`: Use SecurityFindingsTopicArn for security scripts
- `SNS_TOPIC_ARN`: Use FinOpsTopicArn for cost monitoring scripts

### Basic Usage

```bash
# Clone the repository
git clone https://github.com/TocConsulting/aws-helper-scripts.git
cd aws-helper-scripts

# Run any CLI script
cd aws-cost-monitor/
python aws_cost_monitor_cli.py --threshold 1000

# Check for public S3 buckets
cd check-public-s3/
python check_public_s3_cli.py

# Deploy Lambda versions (serverless automation)
cd aws-cost-monitor-lambda/
./deploy.sh dev --guided  # First time deployment
./deploy.sh prod          # Subsequent deployments

# Deploy any Lambda function
cd check-public-s3-lambda/
sam build && sam deploy --guided
```

## 💡 Use Cases

### 🏢 Enterprise Security Teams
- **Compliance Auditing**: Automated AWS security posture assessment
- **Vulnerability Management**: Identify public resources and misconfigurations
- **Access Control**: Monitor IAM configurations and MFA compliance

### 💼 Cloud Operations Teams  
- **Cost Optimization**: Track spending patterns and identify waste
- **Resource Management**: Inventory and optimize cloud resources
- **Automation**: Integrate scripts into existing workflows

### 🔧 DevOps Engineers
- **Infrastructure Auditing**: AWS resource configuration assessment
- **Compliance Monitoring**: Automated security and compliance checks
- **Resource Optimization**: Identify and clean up unused resources

## 🔧 AWS SAM (Serverless Application Model) Deployment

**IMPORTANT**: This repository includes 14 Lambda versions of the CLI tools for automated, serverless execution. All Lambda deployments use AWS SAM.

### AWS SAM Requirements

Every `*-lambda/` folder in this repository uses AWS SAM for deployment:

**Required Tools:**
```bash
# AWS SAM CLI (MANDATORY for Lambda deployments)
pip install aws-sam-cli

# Verify installation
sam --version

# Alternative installation methods:
# macOS: brew install aws-sam-cli
# Windows: choco install aws-sam-cli
# Linux: https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/install-sam-cli.html
```

### SAM Deployment Process

**Each Lambda folder contains:**
- `template.yaml` - SAM CloudFormation template
- `deploy.sh` - Automated deployment script
- `samconfig.toml` - SAM configuration file
- `lambda_function.py` - Lambda handler code
- `requirements.txt` - Python dependencies

**Standard Deployment:**
```bash
# Navigate to any Lambda folder
cd aws-cost-monitor-lambda/

# First-time deployment (creates S3 bucket, configures region)
./deploy.sh dev --guided

# Production deployment
./deploy.sh prod

# Manual SAM deployment (alternative)
sam build
sam deploy --guided --stack-name my-stack-name
```

### SAM Template Structure

All Lambda functions use this SAM template pattern:
```yaml
AWSTemplateFormatVersion: '2010-09-09'
Transform: AWS::Serverless-2016-10-31

Parameters:
  Environment: [dev|staging|prod]
  Schedule: "cron(0 9 * * ? *)"  # CloudWatch Events schedule

Resources:
  FunctionName:
    Type: AWS::Serverless::Function
    Properties:
      Runtime: python3.13
      Handler: lambda_function.lambda_handler
      Events:
        ScheduledTrigger:
          Type: Schedule
          Properties:
            Schedule: !Ref Schedule
```

### Automated Scheduling

**All Lambda functions include:**
- **CloudWatch Events scheduling** (cron expressions)
- **Environment-specific parameters** (dev/staging/prod)
- **IAM roles with least privilege permissions**
- **SNS integration** for notifications
- **Structured logging** to CloudWatch

Example scheduled execution:
```bash
# Deploy with custom schedule (daily at 6 AM)
sam deploy --parameter-overrides Schedule="cron(0 6 * * ? *)"
```

## 🔧 Advanced Configuration

Most scripts support configuration through:
- **Environment Variables**: Set AWS regions, thresholds, etc.
- **Command Line Arguments**: Customize behavior per execution
- **SAM Parameters**: Configure Lambda deployment settings
- **Configuration Files**: JSON/YAML configs for complex setups

Example configuration:
```bash
export AWS_REGION=us-west-2
export COST_THRESHOLD=500
export ALERT_EMAIL=admin@company.com
```

## 📈 Integration Examples

### CI/CD Pipeline Integration
```yaml
# GitHub Actions example
- name: AWS Security Audit
  run: |
    python check-public-s3/check_public_s3_cli.py
    python check-iam-users-no-mfa/check_iam_users_no_mfa_cli.py
```

### Monitoring Integration
```bash
# Cron job for daily cost monitoring
0 8 * * * cd /opt/aws-helper-scripts/aws-cost-monitor && python aws_cost_monitor_cli.py
```

## 🛡️ Security Best Practices

- **IAM Permissions**: Scripts use least-privilege AWS permissions
- **Credential Management**: Support for IAM roles and credential files
- **Audit Logging**: All scripts log their activities
- **Safe Defaults**: Conservative settings to prevent accidental changes

## 📊 Output Formats

Scripts support multiple output formats:
- **Console**: Human-readable colored output
- **JSON**: Machine-readable structured data (where applicable)
- **CSV**: Spreadsheet-compatible format (where applicable)

## 🤝 Contributing

We welcome contributions! Please:

1. **Fork** the repository
2. **Create** a feature branch
3. **Add** tests for new functionality
4. **Submit** a pull request

### Development Guidelines
- Follow existing code style and patterns
- Include comprehensive error handling
- Add documentation and examples
- Test across multiple AWS regions/accounts

## 📚 Documentation

Each script includes:
- **Individual README**: Detailed usage instructions
- **Configuration Options**: All available parameters
- **Example Outputs**: Sample results and formats
- **Troubleshooting**: Common issues and solutions

## 🆘 Support

- 🐛 **Issues**: Report bugs via GitHub Issues
- 💬 **Discussions**: Feature requests and questions
- 📖 **Wiki**: Additional documentation and examples

## 🏷️ Versioning

This project follows semantic versioning. Check the [releases page](../../releases) for version history and changelog.

## ⚖️ License

[MIT License](LICENSE) - See LICENSE file for details.

---

<div align="center">

**⭐ Star this repository if you find it useful! ⭐**

*Made with ❤️ for the DevOps and Security community*

</div>
