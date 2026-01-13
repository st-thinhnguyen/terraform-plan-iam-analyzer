import json
import sys
import os
from collections import defaultdict
from typing import List, Dict, Any, Set
import requests


# Load valid IAM services from resources.json
def load_iam_services() -> Set[str]:
    """Load the list of valid IAM service names from resources.json."""
    try:
        resources_file = os.path.join(os.path.dirname(__file__), 'resources.json')
        with open(resources_file, 'r') as f:
            return set(json.load(f))
    except (FileNotFoundError, json.JSONDecodeError):
        print("Warning: Could not load resources.json, using default mappings", file=sys.stderr)
        return set()


IAM_SERVICES = load_iam_services()


def get_service_from_resource_type(resource_type: str) -> str:
    """Map Terraform resource type to IAM service name.
    
    Prioritizes Terraform naming, then checks against resources.json for validation.
    """
    # Custom mappings where Terraform name differs from IAM Explorer service name
    # These are based on actual Terraform provider conventions
    terraform_to_iam_mappings = {
        # VPC and networking resources use EC2 in both Terraform and IAM
        'vpc': 'ec2',
        'subnet': 'ec2',
        'internet': 'ec2',  # aws_internet_gateway
        'nat': 'ec2',  # aws_nat_gateway
        'route': 'ec2',  # aws_route, aws_route_table
        'security': 'ec2',  # aws_security_group
        'eip': 'ec2',  # aws_eip
        'instance': 'ec2',  # aws_instance
        'key': 'ec2',  # aws_key_pair
        'flow': 'ec2',  # aws_flow_log
        'default': 'ec2',  # aws_default_*
        
        # Load balancer - Terraform uses 'lb', IAM uses 'elasticloadbalancing'
        'lb': 'elasticloadbalancing',
        'alb': 'elasticloadbalancing',
        'nlb': 'elasticloadbalancing',
        'elb': 'elasticloadbalancing',
        
        # Database resources
        'db': 'rds',  # aws_db_* resources use RDS
        
        # CloudWatch - Terraform uses 'cloudwatch_log_group', IAM uses 'logs'
        'cloudwatch': 'logs',
        
        # Cognito - need to check which one is in resources.json
        'cognito': 'cognito-identity',  # or 'sso' for identity center
        
        # Non-AWS resources (skip API calls)
        'local': 'local',
        'random': 'random',
        'tls': 'tls',
    }
    
    parts = resource_type.split('_')
    if len(parts) < 2:
        return parts[0]
    
    # Handle non-AWS resources
    if parts[0] in ['local', 'random', 'tls']:
        return parts[0]
    
    # Remove 'aws' or 'data' prefix to get the Terraform service name
    terraform_service = parts[1] if parts[0] in ['aws', 'data'] else parts[0]
    
    # First, check if there's a custom mapping
    if terraform_service in terraform_to_iam_mappings:
        iam_service = terraform_to_iam_mappings[terraform_service]
        return iam_service
    
    # If no custom mapping, use the Terraform service name as-is
    # This respects Terraform's naming convention
    iam_service = terraform_service
    
    # Validate against resources.json if available
    if IAM_SERVICES:
        if iam_service not in IAM_SERVICES:
            # Try common transformations
            alternatives = [
                iam_service.replace('_', '-'),  # underscore to dash
                iam_service.replace('-', '_'),  # dash to underscore
            ]
            for alt in alternatives:
                if alt in IAM_SERVICES:
                    return alt
            
            # If still not found, keep the Terraform name
            # The API call will fail gracefully
    
    return iam_service


def get_api_resource_name(resource_type: str, service: str) -> str:
    """Map Terraform resource name to API resource name for special cases.
    
    Some resources have different names in the permissions API than in Terraform.
    By default, keep the Terraform resource name unchanged.
    """
    # Special mappings where the API resource name differs from Terraform name
    # Most resources use the exact Terraform name, only add exceptions here
    special_mappings = {
        'aws_cloudtrail': 'aws_cloudtrail_trail',
        'aws_cognito_user_pool': 'aws_cognitoidp_user_pool',
        'aws_cognito_user_pool_domain': 'aws_cognitoidp_user_pool_domain',
        'aws_db_parameter_group': 'aws_rds_cluster_parameter_group',
        'aws_db_subnet_group': 'aws_rds_subnet_group',
        'aws_flow_log': 'aws_ec2_log_flow',
        'aws_iam_openid_connect_provider': 'aws_iam_open_id_connect_provider',
        'aws_lb': 'aws_elasticloadbalancing_load_balancer',
        'aws_lb_listener': 'aws_elasticloadbalancing_listener',
        'aws_lb_target_group': 'aws_elasticloadbalancing_target_group',
    }
    
    # Check if this resource has a special mapping
    if resource_type in special_mappings:
        return special_mappings[resource_type]
    
    # Default: return the Terraform resource name unchanged
    # The API should accept the Terraform resource name as-is
    return resource_type
    
    return resource_type


def to_camel_case(text: str) -> str:
    """Convert text to CamelCase without spaces."""
    # Remove 'aws_' prefix if present
    if text.startswith('aws_'):
        text = text[4:]
    
    # Split by underscore and capitalize each word
    words = text.split('_')
    return ''.join(word.capitalize() for word in words)


def analyze_terraform_plan(plan_file: str = "plan.json") -> tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Analyze terraform plan and extract metadata.
    
    Returns:
        tuple: (list of resources, metadata dict with account/region/partition info)
    """
    with open(plan_file, 'r') as f:
        plan = json.load(f)
    
    # Extract metadata
    metadata = {
        'account_id': None,
        'region': None,
        'partition': 'aws',  # default to 'aws'
        'resource_names': defaultdict(set)  # Maps resource type to set of resource names
    }
    
    # Extract region from variables
    region = plan.get('variables', {}).get('region', {}).get('value')
    if region:
        metadata['region'] = region
    
    filtered_changes = []
    for resource in plan.get('resource_changes', []):
        actions = resource.get('change', {}).get('actions', [])

        if "no-op" not in actions:
            resource_type = resource.get('type')
            resource_name = resource.get('name')
            
            # Try to extract account ID from ARNs in the resource
            if not metadata['account_id']:
                after_values = resource.get('change', {}).get('after', {})
                if after_values:
                    # Search for account ID in common fields
                    for key, value in after_values.items():
                        if isinstance(value, str) and 'arn:aws:' in value:
                            # Extract account ID from ARN
                            parts = value.split(':')
                            if len(parts) >= 5 and parts[4].isdigit():
                                metadata['account_id'] = parts[4]
                                metadata['partition'] = parts[1]
                                break
            
            # Store resource names for ARN construction
            if resource_name:
                metadata['resource_names'][resource_type].add(resource_name)
            
            filtered_changes.append({
                'type': resource_type,
                'actions': actions,
                'name': resource_name,
                'change': resource.get('change', {})
            })
    
    grouped = defaultdict(list)
    for change in filtered_changes:
        resource_type = change['type']
        grouped[resource_type].extend(change['actions'])
    
    result = []
    for resource_type, actions in sorted(grouped.items()):
        service = get_service_from_resource_type(resource_type)
        
        result.append({
            'type': resource_type,
            'service': service,
            'actions': sorted(set(actions))
        })
    
    return result, metadata


class PermissionEnricher:    
    def __init__(self, base_url: str = "https://tfgrantless.skillsboost.cloud/assets"):
        self.base_url = base_url
    
    def fetch_permissions(self, service: str, resource_type: str) -> Dict[str, Any]:
        """Fetch permissions from API, converting resource type to match service if needed."""
        # Skip non-AWS resources
        if service in ['local', 'random', 'tls']:
            return {}
        
        # Get the correct API resource name (handles special cases)
        api_resource_type = get_api_resource_name(resource_type, service)
        
        # URL format: {base_url}/{service}/{resource_type}-permissions.json
        url = f"{self.base_url}/{service}/{api_resource_type}-resource-permissions.json"
        
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            data = response.json()

            if api_resource_type in data:
                return data[api_resource_type]
            else:
                print(f"Warning: Resource type '{api_resource_type}' not found in API response for URL: {url}", file=sys.stderr)
                return {}
                
        except json.JSONDecodeError as e:
            # Silent fail for not found resources (empty response)
            return {}
        except requests.HTTPError as e:
            if e.response.status_code == 404:
                # Silent fail for 404 - resource not available in API
                print(f"Warning: Permissions not found (404) for {api_resource_type} at URL: {url}")
                return {}
            else:
                print(f"Warning: HTTP error {e.response.status_code} for {api_resource_type} at URL: {url}", file=sys.stderr)
            return {}
        except requests.RequestException as e:
            print(f"Warning: Failed to fetch permissions for {api_resource_type} at URL: {url} - Error: {e}", file=sys.stderr)
            return {}
    
    def filter_permissions_by_actions(self, permissions_data: Dict[str, Any], actions: List[str]) -> List[str]:
        if not permissions_data:
            return []
        
        required_permissions = []
        
        # Iterate through each action and collect permissions
        for action in actions:
            if action in permissions_data:
                action_perms = permissions_data[action]
                if isinstance(action_perms, list):
                    required_permissions.extend(action_perms)
                elif isinstance(action_perms, str):
                    required_permissions.append(action_perms)
        
        # Return unique permissions
        return sorted(set(required_permissions))
    
    def enrich_results(self, results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        enriched_results = []
        
        for item in results:
            service = item.get('service')
            resource_type = item.get('type')
            actions = item.get('actions', [])
            
            permissions_data = self.fetch_permissions(service, resource_type)
            permissions = self.filter_permissions_by_actions(permissions_data, actions)
            
            enriched_item = {
                **item,
                'permissions': permissions
            }
            
            enriched_results.append(enriched_item)
        
        return enriched_results


def fetch_resource_arn_for_permission(permission: str, iam_explorer_base_url: str = "https://iam-explorer.skillsboost.cloud/json") -> List[str]:
    """Fetch resource ARNs for a single IAM permission from IAM Explorer API.
    
    Args:
        permission: Single IAM permission (e.g., "cloudfront:CreateOriginAccessControl")
        iam_explorer_base_url: Base URL for IAM Explorer API
        
    Returns:
        List of resource ARN patterns for this permission
    """
    if ':' not in permission:
        return []
        
    service, action = permission.split(':', 1)
    url = f"{iam_explorer_base_url}/{service}/{action}.json"
    
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()
        
        # Extract resource ARNs
        resource_arns = data.get('resource_arns', [])
        return resource_arns if resource_arns else []
            
    except (requests.RequestException, json.JSONDecodeError):
        return []


def generate_iam_policy(enriched_results: List[Dict[str, Any]], metadata: Dict[str, Any]) -> Dict[str, Any]:
    """Generate IAM policy by grouping permissions by service and resource ARNs.
    
    Args:
        enriched_results: List of enriched resource data
        metadata: Dict containing account_id, region, partition, and resource_names
    """
    
    # Structure to hold permission mappings: {service: {resource_key: set(permissions)}}
    permission_map = defaultdict(lambda: defaultdict(set))
    
    for item in enriched_results:
        permissions = item.get('permissions', [])
        
        # Skip if no permissions
        if not permissions:
            continue
        
        # Process each permission individually
        for permission in permissions:
            if ':' not in permission:
                continue
                
            service = permission.split(':', 1)[0]
            
            # Fetch resource ARNs for this specific permission
            resource_arns = fetch_resource_arn_for_permission(permission)
            
            if not resource_arns:
                resource_arns = ["please_update_suitable_resources"]
            
            # Create a key from sorted resource ARNs for grouping
            resource_key = tuple(sorted(resource_arns))
            
            # Group permissions by service and resource combination (using set to avoid duplicates)
            permission_map[service][resource_key].add(permission)
    
    # Replace ARN placeholders with actual values from metadata
    def replace_arn_placeholders(arn: str, metadata: Dict[str, Any]) -> str:
        """Replace ${Partition}, ${Region}, ${Account} with actual values."""
        if arn == "*":
            return arn
            
        replacements = {
            '${Partition}': metadata.get('partition', 'aws'),
            '${Region}': metadata.get('region', 'REGION'),
            '${Account}': metadata.get('account_id', 'ACCOUNT_ID'),
        }
        
        result = arn
        for placeholder, value in replacements.items():
            result = result.replace(placeholder, value)
        
        return result
    
    # Generate statements: wildcard resources first, then specific resources
    statements_with_wildcard = []
    statements_without_wildcard = []
    
    for service in sorted(permission_map.keys()):
        for resource_key, perms in sorted(permission_map[service].items()):
            resource_list = [replace_arn_placeholders(arn, metadata) for arn in resource_key]
            
            # Check if wildcard is present
            has_wildcard = "*" in resource_list
            
            if has_wildcard:
                # Separate wildcard and specific ARNs
                wildcard_arns = ["*"]
                specific_arns = [arn for arn in resource_list if arn != "*"]
                
                # Create wildcard statement
                wildcard_statement = {
                    "Effect": "Allow",
                    "Action": sorted(perms),
                    "Resource": "*"
                }
                statements_with_wildcard.append(wildcard_statement)
                
                # Create specific ARN statement if there are any
                if specific_arns:
                    if len(specific_arns) == 1:
                        resource_value = specific_arns[0]
                    else:
                        resource_value = specific_arns
                    
                    specific_statement = {
                        "Effect": "Allow",
                        "Action": sorted(perms),
                        "Resource": resource_value
                    }
                    statements_without_wildcard.append(specific_statement)
            else:
                # No wildcard
                if len(resource_list) == 1:
                    resource_value = resource_list[0]
                else:
                    resource_value = resource_list
                
                statement = {
                    "Effect": "Allow",
                    "Action": sorted(perms),
                    "Resource": resource_value
                }
                statements_without_wildcard.append(statement)
    
    # Combine statements with wildcards first, then specific resources
    all_statements = statements_with_wildcard + statements_without_wildcard
    
    # Create IAM policy document
    policy = {
        "Version": "2012-10-17",
        "Statement": all_statements
    }
    
    return policy


def write_output_file(data: List[Dict[str, Any]], output_file: str = "output.json") -> None:
    with open(output_file, 'w') as f:
        json.dump(data, f, indent=2)
    print(f"Results written to {output_file}", file=sys.stderr)


def write_iam_policy_file(policy: Dict[str, Any], iam_file: str = "iam.json") -> None:
    """Write IAM policy document to file."""
    with open(iam_file, 'w') as f:
        json.dump(policy, f, indent=2)
    print(f"IAM policy written to {iam_file}", file=sys.stderr)


def main():
    """Main entry point."""
    try:
        plan_file = sys.argv[1] if len(sys.argv) > 1 else "plan.json"
        output_file = sys.argv[2] if len(sys.argv) > 2 else "output.json"
        iam_file = sys.argv[3] if len(sys.argv) > 3 else "iam.json"
        
        # Analyze terraform plan and extract metadata
        result, metadata = analyze_terraform_plan(plan_file)
        
        # Print extracted metadata
        print(f"Extracted metadata:", file=sys.stderr)
        print(f"  Region: {metadata.get('region', 'N/A')}", file=sys.stderr)
        print(f"  Account ID: {metadata.get('account_id', 'N/A')}", file=sys.stderr)
        print(f"  Partition: {metadata.get('partition', 'aws')}", file=sys.stderr)
        
        # Enrich with permissions
        enricher = PermissionEnricher()
        enriched_result = enricher.enrich_results(result)
        
        # Write output file
        write_output_file(enriched_result, output_file)
        
        # Generate and write IAM policy with metadata
        iam_policy = generate_iam_policy(enriched_result, metadata)
        write_iam_policy_file(iam_policy, iam_file)

        if not enriched_result:
            sys.exit(1)
            
    except FileNotFoundError:
        print(f"Error: plan.json not found", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in plan file: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()