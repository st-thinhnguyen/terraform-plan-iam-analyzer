# Terraform Plan IAM Analyzer

A Python tool that analyzes Terraform plan files and automatically generates the minimum required AWS IAM permissions for resource provisioning. This tool helps you create least-privilege IAM policies for your Terraform deployments.

## Features

- **Automatic Permission Discovery**: Analyzes Terraform plan JSON files to extract resource changes and fetch required IAM permissions
- **Smart Service Mapping**: Maps Terraform resource types to correct AWS service APIs with extensive built-in mappings
- **Multi-Action Support**: Handles create, update, delete, and read operations
- **ARN Resolution**: Automatically fetches and resolves resource ARN patterns for each permission
- **Metadata Extraction**: Extracts region, account ID, and partition from Terraform plan for accurate ARN generation
- **Ready-to-Use IAM Policies**: Generates properly formatted IAM policy documents with grouped permissions
- **Intelligent Grouping**: Groups permissions by service and resource ARNs for optimal policy structure

## Prerequisites

- Python 3.7+
- `requests` library
- Internet connectivity (to fetch permission data from APIs)

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
2. **Metadata Extraction**: Extracts AWS account ID, region, and partition from ARNs in the plan
3. **Service Mapping**: Maps Terraform resource types to AWS IAM service names using comprehensive built-in mappings
4. **Permission Fetching**: Retrieves required IAM permissions for each resource type and action from the TFGrantless API
5. **ARN Resolution**: Fetches resource ARN patterns for each permission from the IAM Explorer API
6. **Policy Generation**: Groups permissions by service and resource ARNs, then generates a properly formatted IAM policy document

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
- `permissions`: Required IAM permissions for the specified actions

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
        "s3:CreateBucket",
        "s3:GetBucketAcl",
        "s3:PutBucketPolicy"
      ],
      "Resource": "arn:aws:s3:::${BucketName}"
    }
  ]
}
```

**Key Features:**
- Permissions are grouped by service and resource ARN patterns
- Wildcard (`*`) resources are placed in separate statements
- ARN placeholders (`${Partition}`, `${Region}`, `${Account}`) are automatically replaced with actual values from the Terraform plan
- Remaining placeholders (e.g., `${BucketName}`) require manual updates based on your specific resource names

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
| `aws_cognito_user_pool` | `cognito-identity` | Cognito User Pools |
| `aws_iam_*` | `iam` | IAM resources |

### Non-AWS Resources
The tool automatically skips non-AWS resources:
- `local_*` - Local provider resources
- `random_*` - Random provider resources
- `tls_*` - TLS provider resources

## Special Resource Name Mappings

Some resources have different names in the API compared to Terraform:

| Terraform Resource | API Resource Name |
|-------------------|-------------------|
| `aws_cloudtrail` | `aws_cloudtrail_trail` |
| `aws_lb` | `aws_elasticloadbalancing_load_balancer` |
| `aws_lb_listener` | `aws_elasticloadbalancing_listener` |
| `aws_lb_target_group` | `aws_elasticloadbalancing_target_group` |
| `aws_flow_log` | `aws_ec2_log_flow` |
| `aws_db_parameter_group` | `aws_rds_cluster_parameter_group` |
| `aws_db_subnet_group` | `aws_rds_subnet_group` |
| `aws_cognito_user_pool` | `aws_cognitoidp_user_pool` |
| `aws_cognito_user_pool_domain` | `aws_cognitoidp_user_pool_domain` |
| `aws_iam_openid_connect_provider` | `aws_iam_open_id_connect_provider` |

## API Endpoints

The tool fetches data from two APIs:

1. **TFGrantless API** - For resource permissions:
   ```
   https://tfgrantless.skillsboost.cloud/assets/{service}/{resource_type}-resource-permissions.json
   ```

2. **IAM Explorer API** - For resource ARN patterns:
   ```
   https://iam-explorer.skillsboost.cloud/json/{service}/{action}.json
   ```

## Resources Validation

The tool uses a `resources.json` file that contains a list of valid IAM service names. This helps validate service mappings and ensures accuracy when fetching permissions.

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
   python main.py
   ```
   
   Output shows extracted metadata:
   ```
   Extracted metadata:
     Region: us-east-1
     Account ID: 123456789012
     Partition: aws
   Results written to output.json
   IAM policy written to iam.json
   ```

3. **Review the generated files**:
   - Check `output.json` for detailed permission analysis
   - Review `iam.json` for the generated IAM policy

4. **Update resource-specific placeholders**:
   - Replace placeholders like `${BucketName}`, `${RoleName}`, etc. with actual resource names
   - Note that `${Partition}`, `${Region}`, and `${Account}` are already replaced

5. **Apply the IAM policy**:
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

### Missing Permissions

If permissions are missing for a resource:
1. Check if the resource type is correctly mapped to an AWS service
2. Verify the resource exists in the TFGrantless API
3. Check stderr output for API errors or warnings

### ARN Placeholders Not Replaced

If ARN placeholders like `${Account}` aren't replaced:
1. Ensure your Terraform plan includes resources with ARNs
2. Check that the Terraform plan has proper account/region information
3. Verify that ARNs are present in the resource `after` values

### Empty IAM Policy

If the generated IAM policy is empty:
1. Verify the Terraform plan contains resource changes (not just no-ops)
2. Check that the resources are AWS resources (not local/random/tls)
3. Review stderr output for API fetch errors

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
