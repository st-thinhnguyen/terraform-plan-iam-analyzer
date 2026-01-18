import json
import sys
import os
from collections import defaultdict
from typing import List, Dict, Any, Set
import requests

# Global error collector
ERRORS = []


# Load valid IAM services from resources.json
def load_iam_services() -> Set[str]:
    """Load the list of valid IAM service names from resources.json."""
    try:
        with open(os.path.join(os.path.dirname(__file__), 'resources.json')) as f:
            data = json.load(f)
            print(f"Info: Loaded {len(data)} IAM services from resources.json", file=sys.stderr)
            return set(data)
    except FileNotFoundError:
        print("Warning: resources.json not found, validation disabled", file=sys.stderr)
    except json.JSONDecodeError as e:
        print(f"Warning: Invalid JSON in resources.json: {e.msg}", file=sys.stderr)
    return set()


def load_sdk_permission_mappings() -> Dict[str, List[Dict[str, Any]]]:
    """Load SDK method to IAM permission mappings from map.json."""
    try:
        with open(os.path.join(os.path.dirname(__file__), 'map.json')) as f:
            sdk_mappings = json.load(f).get('sdk_method_iam_mappings', {})
            print(f"Info: Loaded {len(sdk_mappings)} SDK mappings from map.json", file=sys.stderr)
            return sdk_mappings
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Warning: Cannot load map.json: {e}", file=sys.stderr)
    return {}


IAM_SERVICES = load_iam_services()
SDK_PERMISSION_MAPPINGS = load_sdk_permission_mappings()


# ============================================================================
# MAPPING TABLES - Update these when you have new mappings
# ============================================================================

# Terraform resource prefix to IAM service name mappings
# Used when Terraform resource prefix differs from the IAM service name
TERRAFORM_TO_IAM_SERVICE_MAPPINGS = {
    # EC2 and Networking - All use 'ec2' service in IAM
    'vpc': 'ec2',              # aws_vpc
    'subnet': 'ec2',           # aws_subnet
    'internet': 'ec2',         # aws_internet_gateway
    'nat': 'ec2',              # aws_nat_gateway
    'route': 'ec2',            # aws_route, aws_route_table
    'security': 'ec2',         # aws_security_group
    'eip': 'ec2',              # aws_eip (Elastic IP)
    'instance': 'ec2',         # aws_instance
    'key': 'ec2',              # aws_key_pair
    'flow': 'ec2',             # aws_flow_log
    'default': 'ec2',          # aws_default_*
    'network': 'ec2',          # aws_network_*
    'volume': 'ec2',           # aws_ebs_volume
    'snapshot': 'ec2',         # aws_ebs_snapshot
    'ami': 'ec2',              # aws_ami
    
    # Load Balancing - All use 'elbv2' service in IAM
    'lb': 'elbv2',   # aws_lb (ALB/NLB)
    'alb': 'elbv2',  # aws_alb (deprecated, use aws_lb)
    'nlb': 'elbv2',  # aws_nlb
    'elb': 'elasticloadbalancing',  # aws_elb (Classic LB)
    
    # Database - RDS service
    'db': 'rds',               # aws_db_* resources
    
    # Logging and Monitoring
    'cloudwatch': 'logs',      # aws_cloudwatch_log_group uses 'logs' service
    
    # Identity and Access
    'cognito': 'cognitoidp',  # aws_cognito_* (user pools use cognitoidp)
    
    # Non-AWS resources (local providers - skip API calls)
    'local': 'local',          # local_* resources
    'random': 'random',        # random_* resources
    'tls': 'tls',              # tls_* resources
}

# Terraform resource name to TFGrantless API resource name mappings
# Used when the API resource name differs from Terraform resource name
TERRAFORM_TO_API_RESOURCE_NAME_MAPPINGS = {
    'aws_cloudtrail': 'aws_cloudtrail_trail',
    'aws_cognito_user_pool': 'aws_cognito_user_pool',  # Fixed: remove 'idp' prefix
    'aws_cognito_user_pool_client': 'aws_cognito_user_pool_client',  # Added
    'aws_cognito_user_pool_domain': 'aws_cognito_user_pool_domain',  # Fixed: remove 'idp' prefix
    'aws_db_parameter_group': 'aws_rds_cluster_parameter_group',
    'aws_db_subnet_group': 'aws_db_subnet_group',  # Fixed: use correct name
    'aws_flow_log': 'aws_ec2_log_flow',
    'aws_iam_openid_connect_provider': 'aws_iam_open_id_connect_provider',
    'aws_lb': 'aws_lb',  # Fixed: elbv2 service uses aws_lb
    'aws_lb_listener': 'aws_lb_listener',  # Fixed: elbv2 service uses aws_lb_listener
    'aws_lb_target_group': 'aws_lb_target_group',  # Fixed: elbv2 service uses aws_lb_target_group
}

# ============================================================================
# END OF MAPPING TABLES
# ============================================================================


def normalize_iam_permission(permission: str) -> str:
    """Normalize IAM permission name using map.json SDK mappings."""
    if not SDK_PERMISSION_MAPPINGS or ':' not in permission:
        return permission
    
    service_prefix, action = permission.split(':', 1)
    
    # Build list of SDK service name patterns to try
    patterns = [
        service_prefix.upper(),
        service_prefix.title(),
        ''.join(w.capitalize() for w in service_prefix.split('-'))
    ]
    
    # Special case for cognito-identity -> try CognitoIdentityServiceProvider
    if service_prefix == 'cognito-identity':
        patterns.extend(['CognitoIdentityServiceProvider', 'CognitoIdentityProvider'])
    
    # Try each pattern
    for pattern in patterns:
        mappings = SDK_PERMISSION_MAPPINGS.get(f"{pattern}.{action}")
        if mappings and mappings[0].get('action'):
            normalized = mappings[0]['action']
            if normalized != permission:
                print(f"Info: Normalized '{permission}' -> '{normalized}'", file=sys.stderr)
            return normalized
    
    return permission


def expand_permissions_from_map(permissions: List[str]) -> List[str]:
    """Expand permissions using map.json to include all related IAM actions.
    
    The map.json uses SDK method names (e.g., KMS.CreateKey) but we receive
    IAM permission names (e.g., kms:CreateKey). We need to check if the
    SDK method has additional permissions required.
    
    Example: KMS.CreateKey requires both kms:CreateKey and kms:TagResource
    """
    if not SDK_PERMISSION_MAPPINGS:
        return permissions
    
    expanded = []
    seen = set()
    
    for permission in permissions:
        if ':' not in permission:
            if permission not in seen:
                expanded.append(permission)
                seen.add(permission)
            continue
        
        service_prefix, action = permission.split(':', 1)
        
        # Convert IAM permission to SDK method format
        # kms:CreateKey -> KMS.CreateKey
        # s3:GetObject -> S3.GetObject
        sdk_service_patterns = [
            service_prefix.upper(),  # kms -> KMS
            service_prefix.title(),  # s3 -> S3
            ''.join(w.capitalize() for w in service_prefix.split('-'))  # cognito-identity -> CognitoIdentity
        ]
        
        found_mapping = False
        for pattern in sdk_service_patterns:
            sdk_key = f"{pattern}.{action}"
            mappings = SDK_PERMISSION_MAPPINGS.get(sdk_key)
            
            if mappings and isinstance(mappings, list):
                found_mapping = True
                # Add all actions from the mapping
                for mapping in mappings:
                    if isinstance(mapping, dict):
                        action_name = mapping.get('action')
                        if action_name and action_name not in seen:
                            expanded.append(action_name)
                            seen.add(action_name)
                            if len(mappings) > 1 and action_name != permission:
                                print(f"Info: Expanded '{permission}' to include '{action_name}' (from SDK mapping)", file=sys.stderr)
                break
        
        # If no mapping found, just add the original permission
        if not found_mapping and permission not in seen:
            expanded.append(permission)
            seen.add(permission)
    
    return expanded


def get_service_from_resource_type(resource_type: str) -> str:
    """Extract IAM service name from Terraform resource type."""
    if not resource_type.startswith('aws_'):
        print(f"Warning: Non-AWS resource type '{resource_type}', skipping", file=sys.stderr)
        return ''
    
    parts = resource_type[4:].split('_')
    prefix = parts[0] if parts else ''
    
    # Check mapping table first
    if prefix in TERRAFORM_TO_IAM_SERVICE_MAPPINGS:
        mapped_service = TERRAFORM_TO_IAM_SERVICE_MAPPINGS[prefix]
        if mapped_service in {'local', 'random', 'tls'}:
            print(f"Warning: Local provider resource '{resource_type}', skipping", file=sys.stderr)
            return ''
        return mapped_service
    
    # Validate against IAM services
    if IAM_SERVICES and prefix not in IAM_SERVICES:
        print(f"Warning: Service '{prefix}' not in IAM services for '{resource_type}'", file=sys.stderr)
    
    return prefix


def get_api_resource_name(resource_type: str) -> str:
    """Get the API resource name for TFGrantless API."""
    return TERRAFORM_TO_API_RESOURCE_NAME_MAPPINGS.get(resource_type, resource_type)


def analyze_terraform_plan(plan_file: str) -> List[Dict[str, Any]]:
    """Parse Terraform plan and extract resource information."""
    try:
        with open(plan_file) as f:
            plan = json.load(f)
    except FileNotFoundError:
        print(f"Error: Plan file '{plan_file}' not found", file=sys.stderr)
        return []
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in '{plan_file}': {e.msg}", file=sys.stderr)
        return []
    
    # Extract AWS context from plan
    aws_context = {
        'region': plan.get('variables', {}).get('region', {}).get('value', '*'),
        'account': '${Account}',  # Keep as placeholder
        'partition': 'aws'  # Default AWS partition
    }
    
    resources = []
    resource_changes = plan.get('resource_changes', [])
    
    if not resource_changes:
        print("Warning: No resource_changes found in plan", file=sys.stderr)
        return []
    
    print(f"Info: Processing {len(resource_changes)} resource changes", file=sys.stderr)
    print(f"Info: AWS Region: {aws_context['region']}", file=sys.stderr)
    
    for change in resource_changes:
        resource_type = change.get('type')
        if not resource_type:
            print("Warning: Resource missing 'type' field, skipping", file=sys.stderr)
            continue
        
        # Detect data sources via 'mode' field
        mode = change.get('mode', '')
        is_datasource = (mode == 'data')
        
        actions = change.get('change', {}).get('actions', [])
        if not actions:
            print(f"Warning: No actions for resource '{resource_type}', skipping", file=sys.stderr)
            continue
        
        service = get_service_from_resource_type(resource_type)
        if not service:
            continue
        
        resources.append({
            'type': resource_type,
            'service': service,
            'actions': actions,
            'is_datasource': is_datasource,
            'aws_context': aws_context
        })
    
    print(f"Info: Extracted {len(resources)} valid resources", file=sys.stderr)
    return resources


class PermissionEnricher:
    """Fetches and enriches permissions from TFGrantless API."""
    
    def __init__(self):
        self.base_url = "https://tfgrantless.skillsboost.cloud/assets"
        self.session = requests.Session()
    
    def fetch_permissions(self, resource_type: str, is_datasource: bool = False) -> List[str]:
        """Fetch permissions from API with fallback logic."""
        # Special handling for resources with known issues
        if resource_type == 'aws_sqs_queue_policy':
            # API returns empty, use hardcoded permission
            return ['sqs:SetQueueAttributes']
        
        if resource_type == 'aws_flow_log':
            # API doesn't have data yet, use EC2 flow log permissions from SDK
            return ['ec2:CreateFlowLogs', 'ec2:DeleteFlowLogs']
        
        api_resource_name = get_api_resource_name(resource_type)
        
        # Try datasource permissions first if it's a data source
        if is_datasource:
            permissions = self._fetch_with_fallback(api_resource_name, prefer_datasource=True)
        else:
            permissions = self._fetch_with_fallback(api_resource_name, prefer_datasource=False)
        
        # Return raw permissions - normalization happens later in main()
        return permissions
    
    def _fetch_with_fallback(self, resource_name: str, prefer_datasource: bool) -> List[str]:
        """Fetch with fallback between datasource and resource permissions."""
        primary_suffix = '-datasource-permissions.json' if prefer_datasource else '-resource-permissions.json'
        fallback_suffix = '-resource-permissions.json' if prefer_datasource else '-datasource-permissions.json'
        
        # Try primary
        permissions = self._fetch_from_api(resource_name, primary_suffix)
        if permissions:
            return permissions
        
        # Try fallback
        print(f"Info: Trying fallback for '{resource_name}'", file=sys.stderr)
        permissions = self._fetch_from_api(resource_name, fallback_suffix)
        if permissions:
            return permissions
        
        print(f"Error: No permissions found for '{resource_name}'", file=sys.stderr)
        return []
    
    def _fetch_from_api(self, resource_name: str, suffix: str) -> List[str]:
        """Fetch permissions from API endpoint."""
        # Extract service from resource name (e.g., aws_s3_bucket -> s3)
        service = get_service_from_resource_type(resource_name)
        if not service:
            ERRORS.append({
                'step': 'fetch_permissions',
                'resource': resource_name,
                'error': 'Failed to extract service from resource type'
            })
            return []
        
        url = f"{self.base_url}/{service}/{resource_name}{suffix}"
        try:
            response = self.session.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                
                # The API returns nested structure:
                # {"aws_s3_bucket": {"create": ["s3:CreateBucket", ...], "delete": [...], ...}}
                resource_data = data.get(resource_name, {})
                
                # If it's a dict with action categories, flatten all permissions
                if isinstance(resource_data, dict):
                    all_permissions = []
                    for action_category, perms in resource_data.items():
                        if isinstance(perms, list):
                            all_permissions.extend(perms)
                    
                    if all_permissions:
                        print(f"Info: Fetched {len(all_permissions)} permissions from {suffix}", file=sys.stderr)
                        return all_permissions
                # Fallback: if it's already a list
                elif isinstance(resource_data, list):
                    print(f"Info: Fetched {len(resource_data)} permissions from {suffix}", file=sys.stderr)
                    return resource_data
                
                error_msg = f"API returned empty permissions for '{resource_name}'"
                print(f"Warning: {error_msg}", file=sys.stderr)
                ERRORS.append({
                    'step': 'fetch_permissions',
                    'resource': resource_name,
                    'url': url,
                    'error': error_msg
                })
                return []
            else:
                error_msg = f"API returned status {response.status_code}"
                print(f"Warning: {error_msg} for '{url}'", file=sys.stderr)
                ERRORS.append({
                    'step': 'fetch_permissions',
                    'resource': resource_name,
                    'url': url,
                    'error': error_msg
                })
        except requests.RequestException as e:
            error_msg = str(e)
            print(f"Warning: API request failed for '{url}': {error_msg}", file=sys.stderr)
            ERRORS.append({
                'step': 'fetch_permissions',
                'resource': resource_name,
                'url': url,
                'error': f"Request failed: {error_msg}"
            })
        return []
    
    def filter_permissions_by_actions(self, permissions: List[str], actions: List[str]) -> List[str]:
        """Filter permissions based on Terraform actions."""
        if 'create' in actions or 'update' in actions:
            return permissions
        
        # For read/no-op actions, filter to read-only permissions
        read_prefixes = ['Get', 'List', 'Describe', 'Head']
        filtered = [p for p in permissions if any(p.split(':')[1].startswith(prefix) for prefix in read_prefixes)]
        
        if not filtered:
            print(f"Warning: No read permissions found, returning all permissions", file=sys.stderr)
            return permissions
        
        return filtered


def extract_arn_from_sdk_mapping(service: str, action: str) -> List[str]:
    """Extract ARN patterns from map.json SDK mappings."""
    if not SDK_PERMISSION_MAPPINGS:
        return []
    
    # Try different SDK service name patterns
    # cognito-idp -> CognitoIdentityProvider, CognitoIdp
    patterns = [
        service.upper(),
        service.title(),
        ''.join(w.capitalize() for w in service.split('-'))
    ]
    
    # Special mappings for services with multiple name variations
    if service == 'cognito-idp':
        patterns.extend(['CognitoIdentityProvider', 'CognitoIdentityServiceProvider'])
    
    # Search for SDK methods that contain this action
    for pattern in patterns:
        for sdk_key, mappings in SDK_PERMISSION_MAPPINGS.items():
            if not sdk_key.startswith(f"{pattern}."):
                continue
            
            # Check if this SDK method has the action we're looking for
            for mapping in mappings:
                if mapping.get('action', '').lower() == f"{service}:{action}".lower():
                    # Check if there's an ARN override
                    arn_override = mapping.get('arn_override', {})
                    if arn_override and 'template' in arn_override:
                        print(f"Info: Found ARN from map.json for '{service}:{action}': {arn_override['template']}", file=sys.stderr)
                        return [arn_override['template']]
    
    return []


def fetch_resource_arn_for_permission(service: str, permission: str) -> List[str]:
    """Fetch ARN patterns from IAM Explorer API. Returns list of ARN patterns."""
    if ':' not in permission:
        error_msg = f"Invalid permission format '{permission}', expected 'service:action'"
        print(f"Warning: {error_msg}", file=sys.stderr)
        ERRORS.append({
            'step': 'fetch_arn',
            'permission': permission,
            'error': error_msg
        })
        return ['*']
    
    service_part, action = permission.split(':', 1)
    
    # Filter out unsupported services/actions
    if action == 'Options':
        print(f"Warning: Skipping invalid action '{action}' for service '{service_part}'", file=sys.stderr)
        return ['*']
    
    # Skip s3express entirely - not supported in IAM Explorer
    if service_part == 's3express':
        print(f"Info: Skipping s3express permission '{permission}' - not supported", file=sys.stderr)
        return ['*']
    
    # Override service for IAM-specific actions
    # PassRole and CreateServiceLinkedRole belong to IAM service, not the calling service
    if action in ['PassRole', 'CreateServiceLinkedRole']:
        api_service = 'iam'
    else:
        # Map service names for IAM Explorer API
        # application-autoscaling uses 'application-autoscaling' not 'appautoscaling'
        iam_explorer_service_mappings = {
            'elbv2': 'elasticloadbalancing',
            'cognitoidp': 'cognito-idp',
            'appautoscaling': 'application-autoscaling',
        }
        api_service = iam_explorer_service_mappings.get(service, service)
    
    # URL format: https://iam-explorer.skillsboost.cloud/json/{service}/{action}.json
    url = f"https://iam-explorer.skillsboost.cloud/json/{api_service}/{action}.json"
    
    try:
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200 and response.text.strip():
            data = response.json()
            # API returns {"access_level": "...", "resource_arns": [...]}
            resource_arns = data.get('resource_arns', [])
            if resource_arns:
                # Return all ARN patterns
                return resource_arns
            else:
                ERRORS.append({
                    'step': 'fetch_arn',
                    'permission': permission,
                    'url': url,
                    'error': 'No resource_arns in response'
                })
        elif response.status_code == 404:
            # 404 is common for permissions not in IAM Explorer, don't log as error
            pass
        else:
            ERRORS.append({
                'step': 'fetch_arn',
                'permission': permission,
                'url': url,
                'error': f"HTTP {response.status_code}"
            })
    except (requests.RequestException, json.JSONDecodeError) as e:
        ERRORS.append({
            'step': 'fetch_arn',
            'permission': permission,
            'url': url,
            'error': str(e)
        })
    
    # Fallback: Try to extract ARN from map.json SDK mappings
    arn_from_map = extract_arn_from_sdk_mapping(service_part, action)
    if arn_from_map:
        return arn_from_map
    
    return ['*']


def generate_iam_policy(enriched_resources: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Generate IAM policy from enriched resource permissions."""
    # Get AWS context from first resource (all should have same context)
    aws_context = enriched_resources[0].get('aws_context', {}) if enriched_resources else {}
    
    # Collect all unique permissions across all resources
    all_permissions = set()
    
    for resource in enriched_resources:
        permissions = resource.get('permissions', [])
        for permission in permissions:
            if ':' in permission:
                all_permissions.add(permission)
    
    # Group permissions by their ARN patterns (deduplicate globally)
    arn_to_permissions = defaultdict(set)
    
    for permission in all_permissions:
        # Extract service from permission (e.g., 'logs:CreateLogDelivery' -> 'logs')
        permission_service = permission.split(':', 1)[0]
        
        arns = fetch_resource_arn_for_permission(permission_service, permission)
        
        # Replace ARN placeholders with actual values from plan
        processed_arns = []
        for arn in arns:
            arn = arn.replace('${Partition}', aws_context.get('partition', 'aws'))
            arn = arn.replace('${Region}', aws_context.get('region', '*'))
            # Keep ${Account} as placeholder - don't replace it
            processed_arns.append(arn)
        
        # Group permissions by their ARN patterns (as a tuple for hashability)
        arn_key = tuple(sorted(processed_arns))
        arn_to_permissions[arn_key].add(permission)
    
    # Create statements grouped by ARN patterns
    wildcard_statements = []
    specific_statements = []
    
    for arn_tuple, perms in arn_to_permissions.items():
        arns_list = list(arn_tuple)
        resource_value = arns_list if arns_list != ['*'] else '*'
        
        statement = {
            'Effect': 'Allow',
            'Action': sorted(list(perms)),
            'Resource': resource_value
        }
        
        # Separate wildcard and specific resource statements
        if resource_value == '*':
            wildcard_statements.append(statement)
        else:
            specific_statements.append(statement)
    
    # Combine with wildcard statements first
    statements = wildcard_statements + specific_statements
    
    policy = {
        'Version': '2012-10-17',
        'Statement': statements
    }
    
    print(f"Info: Generated IAM policy with {len(statements)} statements ({len(wildcard_statements)} wildcard, {len(specific_statements)} specific)", file=sys.stderr)
    return policy


def write_iam_policy_file(policy: Dict[str, Any], output_file: str):
    """Write IAM policy to file."""
    try:
        with open(output_file, 'w') as f:
            json.dump(policy, f, indent=2)
        print(f"Info: IAM policy written to '{output_file}'", file=sys.stderr)
    except IOError as e:
        print(f"Error: Failed to write '{output_file}': {e}", file=sys.stderr)


def main():
    """Main entry point."""
    plan_file = 'plan.json'
    output_file = 'output.json'
    iam_policy_file = 'iam.json'
    
    print("Step 1: Analyzing Terraform plan...", file=sys.stderr)
    resources = analyze_terraform_plan(plan_file)
    
    if not resources:
        print("Error: No resources to process", file=sys.stderr)
        sys.exit(1)
    
    print("\nStep 2: Fetching permissions from TFGrantless API...", file=sys.stderr)
    enricher = PermissionEnricher()
    enriched_resources = []
    
    for resource in resources:
        permissions = enricher.fetch_permissions(
            resource['type'],
            resource.get('is_datasource', False)
        )
        
        filtered_permissions = enricher.filter_permissions_by_actions(
            permissions,
            resource['actions']
        )
        
        # Normalize permissions using map.json AFTER fetching from API
        normalized_permissions = [normalize_iam_permission(p) for p in filtered_permissions]
        
        # Expand permissions to include all related IAM actions from map.json
        # Example: KMS.CreateKey requires both kms:CreateKey and kms:TagResource
        expanded_permissions = expand_permissions_from_map(normalized_permissions)
        
        enriched_resource = resource.copy()
        enriched_resource['permissions'] = expanded_permissions
        enriched_resources.append(enriched_resource)
    
    # Write intermediate output
    try:
        with open(output_file, 'w') as f:
            json.dump(enriched_resources, f, indent=2)
        print(f"\nStep 3: Enriched permissions written to '{output_file}'", file=sys.stderr)
    except IOError as e:
        print(f"Error: Failed to write '{output_file}': {e}", file=sys.stderr)
        sys.exit(1)
    
    print("\nStep 4: Generating IAM policy...", file=sys.stderr)
    iam_policy = generate_iam_policy(enriched_resources)
    
    print("\nStep 5: Writing IAM policy...", file=sys.stderr)
    write_iam_policy_file(iam_policy, iam_policy_file)
    
    print(f"\n✓ Complete! IAM policy generated at '{iam_policy_file}'", file=sys.stderr)
    
    # Write errors to error.json
    error_file = 'error.json'
    if ERRORS:
        try:
            with open(error_file, 'w') as f:
                json.dump({
                    'total_errors': len(ERRORS),
                    'errors': ERRORS
                }, f, indent=2)
            print(f"⚠ {len(ERRORS)} errors logged to '{error_file}'", file=sys.stderr)
        except IOError as e:
            print(f"Error: Failed to write '{error_file}': {e}", file=sys.stderr)
    else:
        print("✓ No errors encountered", file=sys.stderr)


if __name__ == '__main__':
    main()