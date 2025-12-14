import boto3
import argparse
import sys
import json
from datetime import datetime
import os # Import os for path manipulation

def find_dangling_security_groups(region, dry_run=True, output_file_base=None):
    """
    Finds and reports Security Groups that are not attached to any asset and 
    are not referenced by any other Security Group.

    :param region: The AWS region to check.
    :param dry_run: If True, prints CLI commands. If False, executes deletion.
    :param output_file_base: Base name for output files (e.g., 'report').
    """
    
    # --- FILE NAME SETUP (NEW LOGIC) ---
    report_txt_file = None
    report_json_file = None
    if output_file_base:
        # Automatically append .txt and .json extensions
        report_txt_file = output_file_base + ".txt"
        report_json_file = output_file_base + ".json"
        
        # Clear existing files before starting the new report
        if os.path.exists(report_txt_file):
            os.remove(report_txt_file)
        if os.path.exists(report_json_file):
            os.remove(report_json_file)
    
    # Use Boto3 session to automatically pick up the profile set via AWS_PROFILE
    session = boto3.Session(region_name=region)
    ec2 = session.client('ec2')
    
    # 1. Get ALL Security Groups
    try:
        all_sgs = ec2.describe_security_groups()['SecurityGroups']
    except Exception as e:
        report = f"Error connecting to region {region}: {e}"
        print(report, file=sys.stderr)
        return
        
    sg_details = {sg['GroupId']: sg for sg in all_sgs}
    # ... (rest of the script remains the same for data collection) ...

    # --- SET A: Security Groups Attached to an ENI ---
    enis = ec2.describe_network_interfaces()['NetworkInterfaces']
    attached_sg_ids = set()
    for eni in enis:
        for group in eni.get('Groups', []):
            attached_sg_ids.add(group['GroupId'])

    # --- SET B & C: Security Groups Referenced by others or themselves ---
    referenced_by_other_sg_ids = set()
    self_referenced_sg_ids = set()

    for current_sg_id, current_sg in sg_details.items():
        is_self_referenced = False
        
        # Check both Ingress and Egress rules
        for permissions in [current_sg.get('IpPermissions', []), current_sg.get('IpPermissionsEgress', [])]:
            for perm in permissions:
                for pair in perm.get('UserIdGroupPairs', []):
                    ref_sg_id = pair.get('GroupId')
                    
                    if ref_sg_id:
                        if ref_sg_id == current_sg_id:
                            is_self_referenced = True
                        else:
                            referenced_by_other_sg_ids.add(ref_sg_id)

        if is_self_referenced:
            self_referenced_sg_ids.add(current_sg_id)

    # --- FINAL CALCULATION ---
    
    # 1. Filter out the 'default' Security Groups from the master list
    non_default_sg_ids = {sg['GroupId'] for sg in all_sgs if sg.get('GroupName') != 'default'}

    # 2. Protected SGs = Attached SGs OR Referenced by Others
    protected_sg_ids = attached_sg_ids.union(referenced_by_other_sg_ids)
    
    # 3. Dangling Candidates = (All NON-DEFAULT SGs) MINUS Protected SGs
    dangling_candidates = non_default_sg_ids - protected_sg_ids
    
    # --- REPORT GENERATION ---
    
    total_protected = len(all_sgs) - len(dangling_candidates)
    
    report_data = {
        "metadata": {
            "timestamp": datetime.now().isoformat(),
            "region": region,
            "execution_mode": "DRY RUN" if dry_run else "LIVE DELETE",
            "total_sgs_found": len(all_sgs),
        },
        "report_summary": {
            "protected_sgs": total_protected,
            "dangling_candidates": len(dangling_candidates)
        },
        "dangling_groups": []
    }
    
    # Iterate through candidates and prepare the report
    for sg_id in sorted(list(dangling_candidates)):
        sg_name = sg_details[sg_id].get('GroupName', 'No Name')
        is_self_referenced_flag = sg_id in self_referenced_sg_ids
        
        status = 'DELETE CANDIDATE'
        cli_command = f"aws ec2 delete-security-group --group-id {sg_id} --region {region}"
        action = cli_command if dry_run else 'EXECUTED'
            
        if not dry_run:
            # --- LIVE DELETION EXECUTION ---
            try:
                ec2.delete_security_group(GroupId=sg_id)
                action = 'SUCCESSFULLY DELETED'
            except Exception as e:
                action = f"DELETE FAILED: {e}"

        report_data["dangling_groups"].append({
            "sg_id": sg_id,
            "sg_name": sg_name,
            "is_self_referenced": is_self_referenced_flag,
            "status": status,
            "action": action
        })

    # --- OUTPUT HANDLING (UPDATED LOGIC) ---
    
    def print_to_target(text):
        """Helper to print to both console and file if specified."""
        print(text)
        if report_txt_file:
            with open(report_txt_file, 'a') as f:
                f.write(text + '\n')

    print_to_target("-" * 60)
    print_to_target(f"--- SG AUDIT REPORT | Region: {region} | Mode: {report_data['metadata']['execution_mode']} ---")
    print_to_target("-" * 60)
    print_to_target(f"Total SGs found: {report_data['metadata']['total_sgs_found']}")
    print_to_target(f"Protected SGs (In Use or System): {report_data['report_summary']['protected_sgs']}")
    print_to_target(f"Dangling Candidates (Deletable): {report_data['report_summary']['dangling_candidates']}")
    print_to_target("-" * 60)

    if dangling_candidates:
        for item in report_data["dangling_groups"]:
            ref_flag = ' (Self-Ref)' if item['is_self_referenced'] else ''
            print_to_target(f"[{item['status']}{ref_flag}] {item['sg_id']} ({item['sg_name']})")
            if dry_run:
                print_to_target(f"   -> CLI Command: {item['action']}")
            else:
                print_to_target(f"   -> Result: {item['action']}")
    else:
        print_to_target("No deletable dangling security groups found. Account is tidy!")
    
    print_to_target("-" * 60)
    if report_txt_file:
        print(f"Full text report saved to: {report_txt_file}")
        # Save the full JSON structure for easy parsing
        with open(report_json_file, 'w') as f:
            json.dump(report_data, f, indent=4)
        print(f"Structured JSON report saved to: {report_json_file}")


# --- Argument Parsing Setup ---

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Audit AWS Security Groups to find and optionally delete 'dangling' SGs.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument(
        'region',
        type=str,
        help='The AWS region to audit (e.g., us-west-2).'
    )
    
    parser.add_argument(
        'mode',
        type=str,
        nargs='?', # Makes this argument optional
        default='dry-run',
        choices=['dry-run', 'live-delete'],
        help='Execution mode:\n'
             '  dry-run (default): Prints deletion commands.\n'
             '  live-delete: Executes deletion of identified SGs (USE WITH EXTREME CAUTION).'
    )
    
    parser.add_argument(
        '-o', '--output',
        type=str,
        default=None,
        help='Optional: Base file name to write the reports (e.g., "audit_run_01"). Creates .txt and .json files.'
    )

    args = parser.parse_args()

    # Execution logic based on arguments
    is_dry = args.mode.lower() == 'dry-run'

    find_dangling_security_groups(
        region=args.region,
        dry_run=is_dry,
        output_file_base=args.output # Pass the base name here
    )
