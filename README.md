# AWS Security Group Audit/Cleanup Script (dangling_sg.py)

A robust Python script utilizing Boto3 to audit an AWS account for "dangling" or unused Security Groups (SGs) and provides options for safe deletion.

---

## What This Script Does

This script analyzes all Security Groups in a specified AWS region to determine if they are actively in use. A Security Group is flagged as a "dangling" candidate for deletion if **BOTH** of the following conditions are met:

1.  It is **NOT** attached to any Elastic Network Interface (ENI). (Covers EC2 instances, RDS, ELB/ALB, EKS nodes, Lambda VPCs, etc.)
2.  It is **NOT** referenced in the ingress or egress rules of any *other* Security Group.

### Key Logic Feature: Self-Reference Handling

The script employs advanced logic to catch a common, yet often overlooked, category of unused Security Groups: **self-referencing groups that are detached from all resources**.

- **The Self-Reference Pattern**: Many network designs use a security group ID in its own inbound rule (`sg-xxxxxx -> sg-xxxxxx`). This is a standard way to ensure all members *currently* or *future* assigned to that group can communicate with each other on specific ports.

- **The Orphaned State**: A basic audit tool might incorrectly see this self-reference and decide the SG is "in use" or "protected." However, if a self-referencing SG is **not attached to any ENI**, it serves no function. It is an **orphaned network policy**.

- **Script Action**: This script correctly identifies these groups, flags them as delete candidates, and explicitly labels them as (`Self-Ref`). This is valuable because these groups are functionally useless and should be cleaned up. Deleting them **will not** impact any active network traffic, as no resources are currently assigned to them.

This intelligent filtering ensures the highest degree of cleanup by targeting SGs that other tools might miss.

---

## Security and Compliance Benefits

Using this script regularly offers significant security and compliance advantages:

* **Reduces Attack Surface:** Every active Security Group, even an unused one, is a potential misconfiguration risk. Removing dangling SGs ensures that only necessary network rules exist, significantly reducing the environment's attack surface.
* **Improves Auditing Clarity:** Clears up clutter in the AWS console, making it easier for security auditors and engineers to review active, functional network policies without being distracted by unnecessary SGs.
* **Prevents Security Group Sprawl:** Ensures infrastructure-as-code deployments or manual resource provisioning don't leave behind residual, unmanaged security rules.
* **Compliance with Least Privilege:** Helps maintain a cleaner, more controlled environment, aiding in compliance with frameworks that mandate strict control over network access rules.

---

## Prerequisites

1.  **Python 3.x**
2.  **Boto3 and AWS CLI:**
    ```bash
    pip install boto3
    ```
3.  **AWS Credentials:** A configured local AWS profile with the necessary permissions (see next section).

---

## How to Use the Script

### Step 1: Configure AWS Profiles

The script relies on the AWS CLI/Boto3 standard configuration to find credentials. When auditing multiple accounts, you **must** use a **Named Profile** with the appropriate **read-only permissions** for the target account.

#### A. Set up the Profile

Ensure your `~/.aws/credentials` and `~/.aws/config` files contain the necessary profile (e.g., `audit-new-account`).

#### B. Select the Profile (CRITICAL)

Before running the script, set the `AWS_PROFILE` environment variable in your terminal session.

```bash
# Example: Setting the profile named 'audit-new-account'
export AWS_PROFILE=audit-new-account
```

### Step 2: Execution

The script uses `argparse` for easy command-line control.

### Syntax

```
Bash
python dangling_sg.py <region> [mode] [-o <output_file>]
```

|Argument|Description|Required|Options|Default|
|:-|:-|:-|:-|:-|
|`region`|The AWS region to audit (e.g., `us-east-1`).|**Yes**|Any valid AWS region|N/A|
|`mode`|Controls execution safety.|No|`dry-run`, `live-delete`|`dry-run`|
|`-o`, `--output`|Writes the report to the specified file path.|No|File path (e.g., `report`)|Console output only|

### Examples

1. **Dry Run (Safe Audit to Console - Default Mode)**
   
Checks the `us-west-2` region and lists the AWS CLI commands needed for deletion, but does not execute them.

```
python dangling_sg.py us-west-2
```

2. **Dry Run with File Output**

Checks `us-east-1` and saves the full report and CLI commands to `us_east_1_audit.txt` and to `us_east_1_audit.json`.

```
Bash
python dangling_sg.py us-east-1 -o us_east_1_audit
```

3. **Live Delete (USE WITH EXTREME CAUTION)**

Executes the deletion of all identified dangling Security Groups in the `ap-southeast-2` region. Only run this after thoroughly reviewing a Dry Run report.

```
Bash
python dangling_sg.py ap-southeast-2 live-delete
```

---

## Required IAM Permissions

The IAM User associated with the selected AWS profile only needs **read-only access** for a standard `dry-run` audit. Elevated privileges are needed for the `live-delete` mode.

|Action|Required for|
|:-|:-|
|`ec2:DescribeSecurityGroups`|Core Audit Functionality|
|`ec2:DescribeNetworkInterfaces`|Core Audit Functionality|
|`ec2:DeleteSecurityGroup`|Required ONLY for `live-delete` mode|

### Minimum Read-Only Policy (for `dry-run`)

```
JSON
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ec2:DescribeSecurityGroups",
                "ec2:DescribeNetworkInterfaces"
            ],
            "Resource": "*"
        }
    ]
}
```

---

## Contributors

- [MagVeTs](https://github.com/MagVeTs)





