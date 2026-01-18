# Terraform Plan IAM Analyzer

A Python tool that analyzes Terraform plan files and automatically generates the minimum required AWS IAM permissions for resource provisioning. This tool helps you create least-privilege IAM policies for your Terraform deployments.

## Features

- **Automatic Permission Discovery**: Analyzes Terraform plan JSON files to extract resource changes and fetch required IAM permissions
- **Smart Service Mapping**: Maps Terraform resource types to correct AWS service APIs with extensive built-in mappings
- **Permission Normalization**: Uses `map.json` (19,000+ SDK method mappings) to normalize and correct permission names
- **Permission Expansion**: Automatically adds related permissions (e.g., `kms:CreateKey` → `kms:CreateKey` + `kms:TagResource`)
- **Multi-Action Support**: Handles create, update, delete, and read operations
- **ARN Resolution**: Fetches ARN patterns from IAM Explorer API with fallback to map.json for missing permissions
- **Metadata Extraction**: Extracts region and partition from Terraform plan, keeps `${Account}` as placeholder
- **Error Tracking**: Comprehensive error logging to `error.json` with detailed API failure information
- **Policy Optimization**: Deduplicates permissions and groups by resource ARN, places wildcard resources first
- **Policy Splitting**: Includes `iam-split.py` tool to split large policies into AWS-compliant 6KB chunks
- **Ready-to-Use IAM Policies**: Generates properly formatted IAM policy documents with grouped permissions

## Prerequisites

- Python 3.7+
- `requests` library
- Internet connectivity (to fetch permission data from APIs)
- `map.json` - SDK method to IAM permission mappings (19,010+ entries)
- `resources.json` - Valid IAM service names (231 services)

## Installation

1. Clone the repository:

```bash
git clone <repository-url>
cd IAM-Analyzer
```

2. Create a virtual environment (recommended):

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

### Generate Terraform Plan

First, create a Terraform plan JSON file:

```bash
terraform plan -out=tfplan
terraform show -json tfplan > plan.json
```

### Run the Analyzer

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

## How It Works

1. **Plan Analysis**: Parses the Terraform plan JSON to identify resource changes (create, update, delete)
2. **AWS Context Extraction**: Extracts region from plan variables, sets partition to 'aws', keeps `${Account}` as placeholder
3. **Service Mapping**: Maps Terraform resource types to AWS IAM service names using comprehensive built-in mappings
4. **Permission Fetching**: Retrieves required IAM permissions from TFGrantless API (with fallback logic)
5. **Permission Normalization**: Normalizes permission names using map.json SDK mappings (e.g., `cognito-identity` → `cognito-idp`)
6. **Permission Expansion**: Adds related permissions from map.json (e.g., `CreateKey` → `CreateKey` + `TagResource`)
7. **ARN Resolution**: Fetches ARN patterns from IAM Explorer API, with fallback to map.json for missing permissions
8. **Policy Generation**: Deduplicates permissions, groups by resource ARN, places wildcard resources first
9. **Error Logging**: Writes all API failures and issues to `error.json` for troubleshooting

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
- `service`: AWS IAM service name
- `actions`: Terraform actions (create, update, delete, read)
- `permissions`: Required IAM permissions (normalized and expanded)

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

AWS IAM policy document ready to use with automatically resolved resource ARNs:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:ListPolicies",
        "iam:ListRoles"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "s3:CreateBucket",
        "s3:DeleteBucket",
        "s3:GetBucketAcl"
      ],
      "Resource": "arn:aws:s3:::${BucketName}"
    }
  ]
}
```

**Key Features:**
- Wildcard (`*`) resource statements are placed at the top
- Permissions are deduplicated and grouped by resource ARN patterns
- ARN placeholders: `${Partition}` → `aws`, `${Region}` → `ap-northeast-1`, `${Account}` kept as placeholder
- Remaining placeholders (e.g., `${BucketName}`) require manual updates based on your specific resource names

### `error.json`

Comprehensive error tracking for troubleshooting API issues:

```json
{
  "total_errors": 15,
  "errors": [
    {
      "step": "fetch_arn",
      "permission": "cognito-idp:CreateUserPool",
      "url": "https://iam-explorer.skillsboost.cloud/json/cognito-idp/CreateUserPool.json",
      "error": "Expecting value: line 1 column 1 (char 0)"
    }
  ]
}
```

Contains:
- `step`: Which operation failed (fetch_permissions, fetch_arn)
- `resource` or `permission`: What was being processed
- `url`: The API endpoint that failed
- `error`: Error message details

## Splitting Large Policies

AWS IAM policies have a maximum size limit of 6,144 characters. Use `iam-split.py` to split large policies:

```bash
# Default: reads iam.json, outputs to iam-policies/ folder
python3 iam-split.py

# Custom input/output:
python3 iam-split.py input.json output-folder/
```

This creates multiple policy files (`iam1.json`, `iam2.json`, etc.) that each stay under the 6KB limit while maximizing the number of statements per file.

Example output:
```
Info: Created 'iam-policies/iam1.json' with 45 statements (6120 chars)
Info: Created 'iam-policies/iam2.json' with 38 statements (5890 chars)

Success: Split policy into 2 files in 'iam-policies'
Total statements: 83
Total size: 12010 characters
```

## Service Mappings

The tool automatically handles AWS service mappings for Terraform resources. Here are some key mappings:

### Networking Resources
| Terraform Resource | AWS Service | Notes |
|-------------------|-------------|-------|
| `aws_vpc`, `aws_subnet` | `ec2` | VPC and subnet resources |
| `aws_route_table`, `aws_route` | `ec2` | Routing resources |
| `aws_security_group` | `ec2` | Security group resources |
| `aws_internet_gateway`, `aws_nat_gateway` | `ec2` | Gateway resources |
| `aws_eip` | `ec2` | Elastic IP addresses |

### Compute & Load Balancing
| Terraform Resource | AWS Service | Notes |
|-------------------|-------------|-------|
| `aws_instance` | `ec2` | EC2 instances |
| `aws_lb`, `aws_alb`, `aws_nlb` | `elasticloadbalancing` | Load balancers |
| `aws_lb_listener` | `elasticloadbalancing` | Load balancer listeners |
| `aws_lb_target_group` | `elasticloadbalancing` | Target groups |

### Database & Storage
| Terraform Resource | AWS Service | Notes |
|-------------------|-------------|-------|
| `aws_db_*` | `rds` | RDS database resources |
| `aws_s3_bucket` | `s3` | S3 buckets |

### Monitoring & Identity
| Terraform Resource | AWS Service | Notes |
|-------------------|-------------|-------|
| `aws_cloudwatch_log_group` | `logs` | CloudWatch Logs |
| `aws_cloudtrail` | `cloudtrail` | CloudTrail trails |
| `aws_cognito_user_pool` | `cognitoidp` | Cognito User Pools (auto-normalized from cognito-identity) |
| `aws_iam_*` | `iam` | IAM resources |

### Filtered Resources
The tool automatically filters out unsupported resources:
- `s3express:*` - S3 Express permissions (not yet in IAM Explorer)
- `local_*` - Local provider resources
- `random_*` - Random provider resources
- `tls_*` - TLS provider resources

## Special Resource Name Mappings

Some resources have different names in the API compared to Terraform:

| Terraform Resource | API Resource Name | Notes |
|-------------------|-------------------|-------|
| `aws_cloudtrail` | `aws_cloudtrail_trail` | |
| `aws_cognito_user_pool` | `aws_cognito_user_pool` | Uses cognitoidp service |
| `aws_cognito_user_pool_client` | `aws_cognito_user_pool_client` | Uses cognitoidp service |
| `aws_cognito_user_pool_domain` | `aws_cognito_user_pool_domain` | Uses cognitoidp service |
| `aws_db_parameter_group` | `aws_rds_cluster_parameter_group` | |
| `aws_db_subnet_group` | `aws_db_subnet_group` | Fixed from aws_rds_subnet_group |
| `aws_flow_log` | `aws_ec2_log_flow` | Special handling with hardcoded permissions |
| `aws_iam_openid_connect_provider` | `aws_iam_open_id_connect_provider` | |
| `aws_lb` | `aws_lb` | Uses elbv2 service |
| `aws_lb_listener` | `aws_lb_listener` | Uses elbv2 service |
| `aws_lb_target_group` | `aws_lb_target_group` | Uses elbv2 service |
| `aws_sqs_queue_policy` | N/A | Hardcoded to sqs:SetQueueAttributes |

## Data Sources

The tool uses multiple data sources for accurate permission generation:

### 1. TFGrantless API
Fetches Terraform resource permissions:
```
https://tfgrantless.skillsboost.cloud/assets/{service}/{resource_type}-{type}-permissions.json
```
- Returns nested structure with action categories (create, delete, put, read, update)
- Automatically flattened to extract all permissions

### 2. IAM Explorer API
Fetches ARN patterns for permissions:
```
https://iam-explorer.skillsboost.cloud/json/{service}/{action}.json
```
- Returns `{"access_level": "...", "resource_arns": [...]}`
- Service name mappings: `elbv2` → `elasticloadbalancing`, `cognitoidp` → `cognito-idp`, `appautoscaling` → `application-autoscaling`
- Special handling: `iam:PassRole` and `iam:CreateServiceLinkedRole` always use `iam` service

### 3. map.json (Local)
SDK method to IAM permission mappings (19,010+ entries):
- **Permission Normalization**: Corrects permission names (e.g., `cognito-identity` → `cognito-idp`)
- **Permission Expansion**: Adds related permissions (e.g., `KMS.CreateKey` → `[kms:CreateKey, kms:TagResource]`)
- **ARN Fallback**: Extracts ARN patterns when IAM Explorer doesn't have data
- Example entry:
  ```json
  "KMS.CreateKey": [
    {"action": "kms:CreateKey"},
    {"action": "kms:TagResource", "arn_override": {"template": "arn:${Partition}:kms:${Region}:${Account}:key/${KeyId}"}}
  ]
  ```

### 4. resources.json (Local)
List of 231 valid IAM service names for validation

## Error Handling

The tool handles various error scenarios gracefully:

- **404 Not Found**: Resources not available in the API will have empty permissions arrays; warnings are logged to stderr
- **Network Errors**: Connection issues are logged but don't stop execution
- **Non-AWS Resources**: Local, random, and TLS provider resources are automatically skipped
- **Invalid JSON**: Malformed plan files result in clear error messages
- **Missing Files**: File not found errors provide helpful feedback

All warnings and errors are written to `stderr`, while the main output goes to the specified files.

## Example Workflow

1. **Create Terraform plan**:
   ```bash
   terraform plan -out=tfplan
   terraform show -json tfplan > plan.json
   ```

2. **Run the analyzer**:
   ```bash
   python3 main.py
   ```
   
   Output shows processing information:
   ```
   Info: Loaded 231 IAM services from resources.json
   Info: Loaded 19010 SDK mappings from map.json
   Step 1: Analyzing Terraform plan...
   Info: Processing 47 resource changes
   Info: AWS Region: ap-northeast-1
   Info: Extracted 47 valid resources
   
   Step 2: Fetching permissions from TFGrantless API...
   Info: Normalized 'cognito-identity:CreateUserPool' -> 'cognito-idp:CreateUserPool'
   Info: Expanded 'kms:CreateKey' to include 'kms:TagResource' (from SDK mapping)
   
   Step 3: Generating IAM policy...
   Info: Generated IAM policy with 83 statements (12 wildcard, 71 specific)
   ```

3. **Review the generated files**:
   - Check `output.json` for detailed permission analysis
   - Review `iam.json` for the generated IAM policy
   - Check `error.json` for any API failures (if exists)

4. **Split large policies** (if needed):
   ```bash
   python3 iam-split.py
   ```
   Creates `iam-policies/iam1.json`, `iam-policies/iam2.json`, etc.

5. **Update resource-specific placeholders**:
   - Replace placeholders like `${BucketName}`, `${RoleName}`, etc. with actual resource names
   - Note that `${Partition}` and `${Region}` are already replaced
   - `${Account}` is kept as placeholder for flexibility

6. **Apply the IAM policy**:
   - Use the policy in your AWS IAM roles or users
   - Attach to CI/CD pipeline execution roles
   - Create least-privilege policies for Terraform automation

## Limitations

- **Internet Required**: Needs internet connectivity to fetch permission data from APIs
- **API Coverage**: Some resources may not have permission data available in the TFGrantless API
- **Manual ARN Updates**: Resource-specific placeholders (e.g., `${BucketName}`) require manual updates
- **Plan-Only Analysis**: Only analyzes resource changes in the plan; doesn't validate existing infrastructure
- **No Condition Support**: Generated policies don't include IAM condition statements
- **Action-Based**: Only considers actions in the plan (create, update, delete, read)

## Advanced Usage

### Extending Service Mappings

To add new service mappings, edit the `terraform_to_iam_mappings` dictionary in `main.py`:

```python
terraform_to_iam_mappings = {
    'your_terraform_prefix': 'iam_service_name',
    # ...
}
```

### Adding Special Resource Mappings

To add special resource name mappings, edit the `special_mappings` dictionary in the `get_api_resource_name()` function:

```python
special_mappings = {
    'aws_your_resource': 'aws_api_resource_name',
    # ...
}
```

## Troubleshooting

### Check error.json First

Always check `error.json` after running the analyzer. It contains detailed information about API failures:

```json
{
  "total_errors": 15,
  "errors": [
    {
      "step": "fetch_arn",
      "permission": "cognito-idp:CreateUserPool",
      "url": "https://iam-explorer.skillsboost.cloud/json/cognito-idp/CreateUserPool.json",
      "error": "Expecting value: line 1 column 1 (char 0)"
    }
  ]
}
```

### Missing Permissions

If permissions are missing for a resource:
1. Check `error.json` for API errors
2. Verify the resource type is correctly mapped to an AWS service
3. Check if permission normalization is working (look for "Info: Normalized" in stderr)
4. Verify the resource exists in the TFGrantless API
5. For missing IAM Explorer data, check if map.json has the permission (ARN fallback)

### Cognito Permissions Wrong Service

If seeing `cognito-identity` instead of `cognito-idp`:
1. Check that map.json is loaded (should see "Info: Loaded 19010 SDK mappings")
2. Verify normalization is happening (check stderr for "Info: Normalized" messages)
3. The tool auto-fixes: `cognito-identity:CreateUserPool` → `cognito-idp:CreateUserPool`

### ARN Placeholders Not Replaced

Only `${Partition}` and `${Region}` are auto-replaced:
- `${Partition}` → `aws`
- `${Region}` → extracted from plan.json variables (e.g., `ap-northeast-1`)
- `${Account}` → kept as placeholder for flexibility
- Other placeholders (e.g., `${BucketName}`) → require manual updates

### Empty IAM Policy

If the generated IAM policy is empty:
1. Verify the Terraform plan contains resource changes (not just no-ops)
2. Check that the resources are AWS resources (not local/random/tls/s3express)
3. Review `error.json` for API fetch errors
4. Check stderr output for "Info: Generated IAM policy with X statements"

### Policy Too Large

If the policy exceeds 6KB:
```bash
python3 iam-split.py
```
This creates multiple compliant policy files in `iam-policies/` folder.

## Contributing

Contributions are welcome! To contribute:

1. Fork the repository
2. Create a feature branch
3. Add your changes with appropriate tests
4. Update documentation as needed
5. Submit a pull request

### Areas for Contribution

- Additional service and resource mappings
- Support for IAM condition statements
- Enhanced ARN resolution logic
- Better error handling and reporting
- Support for data sources
- Integration with other IAM policy tools

## License

This tool is provided as-is for educational and operational purposes.

## Acknowledgments

This tool uses data from:
- [TFGrantless API](https://tfgrantless.skillsboost.cloud) - For Terraform resource permissions
- [IAM Explorer API](https://iam-explorer.skillsboost.cloud) - For AWS IAM resource ARN patterns

---

**Note**: Always review and test generated IAM policies in a non-production environment before applying them to production systems. This tool provides a starting point for IAM policy creation but may require adjustments based on your specific security requirements.
