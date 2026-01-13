# IAM Analyzer

A Python tool to analyze Terraform plan files and generate AWS IAM permissions required for resource creation, modification, and deletion.

## Features

- Analyzes Terraform plan JSON files to extract resource changes
- Fetches IAM permissions from a remote API for each resource type
- Maps Terraform resource types to correct AWS service APIs
- Generates detailed output with permissions for each resource
- Creates ready-to-use IAM policy documents

## Prerequisites

- Python 3.7+
- `requests` library

## Installation

1. Clone or download this repository

2. Create a virtual environment:

```bash
python3 -m venv venv
```

3. Activate the virtual environment:

```bash
# On macOS/Linux
source venv/bin/activate

# On Windows
venv\Scripts\activate
```

4. Install required dependencies:

```bash
pip install -r requirements.txt
```

## Usage

### Basic Usage

```bash
python main.py
```

This uses default file names:
- Input: `plan.json`
- Output: `output.json`
- IAM Policy: `iam.json`

### Custom File Names

```bash
python main.py <plan_file> <output_file> <iam_file>
```

Example:
```bash
python main.py my-plan.json results.json policy.json
```

## Input Format

The tool expects a Terraform plan JSON file generated using:

```bash
terraform plan -out=tfplan
terraform show -json tfplan > plan.json
```

## Output Files

### `output.json`

Contains detailed analysis of each resource type with:
- `type`: Terraform resource type
- `service`: AWS service name
- `actions`: Terraform actions (create, update, delete, read)
- `permissions`: Required IAM permissions

Example:
```json
[
  {
    "type": "aws_s3_bucket",
    "service": "s3",
    "actions": ["create"],
    "permissions": [
      "s3:CreateBucket",
      "s3:GetBucketAcl",
      "s3:PutBucketPolicy"
    ]
  }
]
```

### `iam.json`

AWS IAM policy document ready to use:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "S3Bucket",
      "Effect": "Allow",
      "Action": [
        "s3:CreateBucket",
        "s3:GetBucketAcl",
        "s3:PutBucketPolicy"
      ],
      "Resource": "please_update_suitable_resources"
    }
  ]
}
```

**Note:** You need to update the `Resource` field with appropriate ARNs for your use case.

## Service Mappings

The tool automatically handles AWS service mappings for Terraform resources:

| Terraform Prefix | AWS Service | Example |
|-----------------|-------------|---------|
| `aws_vpc`, `aws_subnet`, `aws_route` | ec2 | VPC and networking resources |
| `aws_lb`, `aws_alb` | elbv2 | Load balancers |
| `aws_db_*` | rds | Database resources |
| `aws_cloudwatch_log_group` | logs | CloudWatch Logs |
| `aws_cognito_*` | cognito-idp | Cognito User Pools |

## Special Resource Name Mappings

Some resources have different names in the API:

- `aws_cloudtrail` → `aws_cloudtrail_trail`
- `aws_lb` → `aws_elbv2_load_balancer`
- `aws_flow_log` → `aws_ec2_log_flow`
- `aws_db_parameter_group` → `aws_rds_cluster_parameter_group`

## API Endpoint

The tool fetches permission data from:
```
https://tfgrantless.skillsboost.cloud/assets/{service}/{resource_type}-permissions.json
```

## Error Handling

- Resources not found in the API will have empty permissions arrays
- Non-AWS resources (local, random, tls) are skipped
- Network errors are logged to stderr but don't stop execution

## Example Workflow

1. Generate Terraform plan:
```bash
terraform plan -out=tfplan
terraform show -json tfplan > plan.json
```

2. Run the analyzer:
```bash
python main.py
```

3. Review the generated `output.json` and `iam.json`

4. Update the `Resource` fields in `iam.json` with appropriate ARNs

5. Use the IAM policy in your AWS account

## Limitations

- Only analyzes resource changes (create, update, delete operations)
- Requires internet connectivity to fetch permission data
- Some resources may not have permission data available in the API
- Generated IAM policies require manual Resource ARN updates

## Contributing

To add new service mappings or resource name mappings, update the dictionaries in:
- `get_service_from_resource_type()` - for service mappings
- `get_api_resource_name()` - for special resource name cases

## License

This tool is provided as-is for educational and operational purposes.
