#!/usr/bin/env python3
"""
Split large IAM policy file into multiple smaller files.
AWS IAM policies have a maximum size limit of 6144 characters.
"""

import json
import os
import sys
from typing import List, Dict, Any


def calculate_policy_size(statements: List[Dict[str, Any]]) -> int:
    """Calculate the character count of a policy with given statements."""
    policy = {
        'Version': '2012-10-17',
        'Statement': statements
    }
    return len(json.dumps(policy, separators=(',', ':')))


def split_iam_policy(input_file: str, output_dir: str, max_size: int = 6144):
    """Split IAM policy into multiple files that fit within size limit."""
    
    # Load the input policy
    try:
        with open(input_file, 'r') as f:
            policy = json.load(f)
    except FileNotFoundError:
        print(f"Error: File '{input_file}' not found", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in '{input_file}': {e}", file=sys.stderr)
        sys.exit(1)
    
    statements = policy.get('Statement', [])
    if not statements:
        print("Warning: No statements found in policy", file=sys.stderr)
        return
    
    print(f"Info: Loaded policy with {len(statements)} statements", file=sys.stderr)
    
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    # Split statements into multiple policies
    policies = []
    current_statements = []
    
    for statement in statements:
        # Try adding this statement to current batch
        test_statements = current_statements + [statement]
        test_size = calculate_policy_size(test_statements)
        
        if test_size > max_size and current_statements:
            # Current batch would be too large, save it and start new batch
            policies.append(current_statements)
            current_statements = [statement]
        else:
            # Add to current batch
            current_statements.append(statement)
    
    # Don't forget the last batch
    if current_statements:
        policies.append(current_statements)
    
    # Write out the split policies
    for i, statements_batch in enumerate(policies, start=1):
        output_file = os.path.join(output_dir, f'iam{i}.json')
        
        policy_obj = {
            'Version': '2012-10-17',
            'Statement': statements_batch
        }
        
        policy_size = calculate_policy_size(statements_batch)
        
        with open(output_file, 'w') as f:
            json.dump(policy_obj, f, indent=2)
        
        print(f"Info: Created '{output_file}' with {len(statements_batch)} statements ({policy_size} chars)", file=sys.stderr)
    
    print(f"\nSuccess: Split policy into {len(policies)} files in '{output_dir}'", file=sys.stderr)
    
    # Summary
    total_size = sum(calculate_policy_size(p) for p in policies)
    print(f"Total statements: {len(statements)}", file=sys.stderr)
    print(f"Total size: {total_size} characters", file=sys.stderr)


def main():
    """Main entry point."""
    input_file = 'iam.json'
    output_dir = 'iam-policies'
    
    # Allow command line arguments
    if len(sys.argv) > 1:
        input_file = sys.argv[1]
    if len(sys.argv) > 2:
        output_dir = sys.argv[2]
    
    print(f"Splitting IAM policy from '{input_file}' into '{output_dir}/'", file=sys.stderr)
    split_iam_policy(input_file, output_dir)


if __name__ == '__main__':
    main()
