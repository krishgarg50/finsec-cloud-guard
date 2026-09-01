import os
import boto3
from botocore.exceptions import ClientError
from dotenv import load_dotenv

load_dotenv()

class AWSConnector:
    def __init__(self):
        self.session = boto3.Session(
            aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
            aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
            region_name=os.getenv("AWS_DEFAULT_REGION", "eu-north-1")
        )
        self.s3_client = self.session.client("s3")
        self.iam_client = self.session.client("iam")
        self.ec2_client = self.session.client("ec2")
        self.cloudtrail_client = self.session.client("cloudtrail")

    def get_s3_buckets_config(self):
        """Pulls S3 bucket configuration, public access blocks, and server-side encryption."""
        buckets_data = []
        try:
            response = self.s3_client.list_buckets()
            for bucket in response.get("Buckets", []):
                name = bucket["Name"]
                bucket_info = {
                    "name": name,
                    "public_access_block": {},
                    "encryption": None
                }

                # Public Access Block
                try:
                    pab = self.s3_client.get_public_access_block(Bucket=name)
                    bucket_info["public_access_block"] = pab.get("PublicAccessBlockConfiguration", {})
                except ClientError as e:
                    if e.response['Error']['Code'] != 'NoSuchPublicAccessBlockConfiguration':
                        pass

                # Server-Side Encryption
                try:
                    enc = self.s3_client.get_bucket_encryption(Bucket=name)
                    bucket_info["encryption"] = enc.get("ServerSideEncryptionConfiguration", {})
                except ClientError as e:
                    if e.response['Error']['Code'] != 'ServerSideEncryptionConfigurationNotFoundError':
                        pass

                buckets_data.append(bucket_info)
        except ClientError as err:
            print(f"Error fetching S3: {err}")
        return buckets_data

    def get_iam_config(self):
        """Pulls IAM users, policies, MFA devices, and account root summary."""
        iam_data = {"users": [], "account_summary": {}}
        try:
            summary = self.iam_client.get_account_summary()
            iam_data["account_summary"] = summary.get("SummaryMap", {})

            users = self.iam_client.list_users()
            for user in users.get("Users", []):
                user_name = user["UserName"]
                attached_policies = self.iam_client.list_attached_user_policies(UserName=user_name)
                mfa_devices = self.iam_client.list_mfa_devices(UserName=user_name)

                policies_detail = []
                for pol in attached_policies.get("AttachedPolicies", []):
                    pol_arn = pol["PolicyArn"]
                    pol_ver = self.iam_client.get_policy(PolicyArn=pol_arn)["Policy"]["DefaultVersionId"]
                    pol_doc = self.iam_client.get_policy_version(PolicyArn=pol_arn, VersionId=pol_ver)
                    policies_detail.append({
                        "name": pol["PolicyName"],
                        "document": pol_doc["PolicyVersion"]["Document"]
                    })

                iam_data["users"].append({
                    "user_name": user_name,
                    "arn": user["Arn"],
                    "policies": policies_detail,
                    "mfa_active": len(mfa_devices.get("MFADevices", [])) > 0
                })
        except ClientError as err:
            print(f"Error fetching IAM: {err}")
        return iam_data

    def get_security_groups_config(self):
        """Pulls EC2 Security Groups and ingress rules."""
        sg_data = []
        try:
            response = self.ec2_client.describe_security_groups()
            sg_data = response.get("SecurityGroups", [])
        except ClientError as err:
            print(f"Error fetching Security Groups: {err}")
        return sg_data

    def get_cloudtrail_config(self):
        """Pulls CloudTrail status and trails."""
        trails_data = []
        try:
            response = self.cloudtrail_client.describe_trails()
            for trail in response.get("trailList", []):
                trail_arn = trail.get("TrailARN")
                status = self.cloudtrail_client.get_trail_status(Name=trail_arn)
                trails_data.append({
                    "name": trail.get("Name"),
                    "arn": trail_arn,
                    "is_logging": status.get("IsLogging", False),
                    "is_multi_region": trail.get("IsMultiRegionTrail", False)
                })
        except ClientError as err:
            print(f"Error fetching CloudTrail: {err}")
        return trails_data