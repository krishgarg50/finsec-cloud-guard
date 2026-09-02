import os
import time
import boto3
from botocore.exceptions import ClientError
from dotenv import load_dotenv

load_dotenv()

# Edge Case Handling: Retry logic with exponential backoff for API rate limits
def retry_with_backoff(max_retries=3):
    def decorator(func):
        def wrapper(*args, **kwargs):
            retries = 0
            while retries <= max_retries:
                try:
                    return func(*args, **kwargs)
                except ClientError as e:
                    error_code = e.response.get('Error', {}).get('Code', '')
                    if error_code in ['Throttling', 'ThrottlingException', 'RequestLimitExceeded']:
                        sleep_time = (2 ** retries)
                        print(f"API Rate limited. Retrying {func.__name__} in {sleep_time} seconds...")
                        time.sleep(sleep_time)
                        retries += 1
                    else:
                        raise e
            return [] # Edge Case Handling: Return empty list on failure, no crash
        return wrapper
    return decorator

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
        self.rds_client = self.session.client("rds") # Added RDS client

    @retry_with_backoff()
    def get_s3_buckets_config(self):
        buckets_data = []
        try:
            response = self.s3_client.list_buckets()
            # Edge Case: Zero resources returns empty list naturally here
            for bucket in response.get("Buckets", []):
                name = bucket["Name"]
                bucket_info = {"name": name, "public_access_block": {}, "encryption": None, "versioning": None}
                
                # Public Access Block
                try:
                    pab = self.s3_client.get_public_access_block(Bucket=name)
                    bucket_info["public_access_block"] = pab.get("PublicAccessBlockConfiguration", {})
                except ClientError as e:
                    pass # Edge Case: No policy is not a crash, just pass

                # Server-Side Encryption
                try:
                    enc = self.s3_client.get_bucket_encryption(Bucket=name)
                    bucket_info["encryption"] = enc.get("ServerSideEncryptionConfiguration", {})
                except ClientError as e:
                    pass
                
                # Versioning
                try:
                    ver = self.s3_client.get_bucket_versioning(Bucket=name)
                    bucket_info["versioning"] = ver.get("Status", "Unversioned")
                except ClientError as e:
                    pass

                buckets_data.append(bucket_info)
        except ClientError as err:
            print(f"Error fetching S3: {err}")
        return buckets_data

    @retry_with_backoff()
    def get_iam_config(self):
        iam_data = {"users": [], "account_summary": {}}
        try:
            summary = self.iam_client.get_account_summary()
            iam_data["account_summary"] = summary.get("SummaryMap", {})

            users = self.iam_client.list_users()
            for user in users.get("Users", []):
                user_name = user["UserName"]
                attached_policies = self.iam_client.list_attached_user_policies(UserName=user_name)
                mfa_devices = self.iam_client.list_mfa_devices(UserName=user_name)
                
                # Fetch Access Keys for Unused Access Key rule
                access_keys = self.iam_client.list_access_keys(UserName=user_name)
                keys_detail = []
                for key in access_keys.get("AccessKeyMetadata", []):
                    key_id = key["AccessKeyId"]
                    try:
                        last_used = self.iam_client.get_access_key_last_used(AccessKeyId=key_id)
                        keys_detail.append({
                            "key_id": key_id,
                            "last_used_date": last_used.get("AccessKeyLastUsed", {}).get("LastUsedDate")
                        })
                    except ClientError:
                        pass

                policies_detail = []
                for pol in attached_policies.get("AttachedPolicies", []):
                    pol_arn = pol["PolicyArn"]
                    pol_ver = self.iam_client.get_policy(PolicyArn=pol_arn)["Policy"]["DefaultVersionId"]
                    pol_doc = self.iam_client.get_policy_version(PolicyArn=pol_arn, VersionId=pol_ver)
                    policies_detail.append({"name": pol["PolicyName"], "document": pol_doc["PolicyVersion"]["Document"]})

                iam_data["users"].append({
                    "user_name": user_name,
                    "arn": user["Arn"],
                    "policies": policies_detail,
                    "mfa_active": len(mfa_devices.get("MFADevices", [])) > 0,
                    "access_keys": keys_detail
                })
        except ClientError as err:
            print(f"Error fetching IAM: {err}")
        return iam_data

    @retry_with_backoff()
    def get_security_groups_config(self):
        try:
            return self.ec2_client.describe_security_groups().get("SecurityGroups", [])
        except ClientError:
            return []

    @retry_with_backoff()
    def get_cloudtrail_config(self):
        trails_data = []
        try:
            response = self.cloudtrail_client.describe_trails()
            for trail in response.get("trailList", []):
                trail_arn = trail.get("TrailARN")
                status = self.cloudtrail_client.get_trail_status(Name=trail_arn)
                trails_data.append({"name": trail.get("Name"), "arn": trail_arn, "is_logging": status.get("IsLogging", False)})
        except ClientError:
            pass
        return trails_data

    @retry_with_backoff()
    def get_ebs_volumes_config(self):
        """Pulls EBS volumes for encryption checks."""
        try:
            return self.ec2_client.describe_volumes().get("Volumes", [])
        except ClientError:
            return []

    @retry_with_backoff()
    def get_rds_instances_config(self):
        """Pulls RDS instances for encryption and public access checks."""
        try:
            return self.rds_client.describe_db_instances().get("DBInstances", [])
        except ClientError:
            return []