import os
import boto3
from botocore.exceptions import ClientError
from dotenv import load_dotenv

# Load credentials from your .env file
load_dotenv()

class AWSConnector:
    def __init__(self):
        # Set up the AWS session
        self.session = boto3.Session(
            aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
            aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
            region_name=os.getenv("AWS_DEFAULT_REGION", "eu-north-1")
        )
        self.s3_client = self.session.client("s3")
        self.iam_client = self.session.client("iam")

    def get_s3_buckets_config(self):
        """Pulls all S3 buckets and their public access/policy status."""
        buckets_data = []
        try:
            response = self.s3_client.list_buckets()
            for bucket in response.get("Buckets", []):
                name = bucket["Name"]
                bucket_info = {"name": name, "public_access_block": {}, "policy": None}

                # Get Public Access Block
                try:
                    pab = self.s3_client.get_public_access_block(Bucket=name)
                    bucket_info["public_access_block"] = pab.get("PublicAccessBlockConfiguration", {})
                except ClientError as e:
                    if e.response['Error']['Code'] != 'NoSuchPublicAccessBlockConfiguration':
                        pass

                # Get Bucket Policy
                try:
                    pol = self.s3_client.get_bucket_policy(Bucket=name)
                    bucket_info["policy"] = pol.get("Policy")
                except ClientError as e:
                    if e.response['Error']['Code'] != 'NoSuchBucketPolicy':
                        pass

                buckets_data.append(bucket_info)
        except ClientError as err:
            print(f"Error fetching S3: {err}")
        return buckets_data

    def get_iam_config(self):
        """Pulls IAM users, policies, and account MFA status via iam:GetCredentialReport style data."""
        iam_data = {"users": [], "account_summary": {}}
        try:
            # Get Root MFA status
            summary = self.iam_client.get_account_summary()
            iam_data["account_summary"] = summary.get("SummaryMap", {})

            # Get Users and their policies
            users = self.iam_client.list_users()
            for user in users.get("Users", []):
                user_name = user["UserName"]
                attached_policies = self.iam_client.list_attached_user_policies(UserName=user_name)
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
                    "policies": policies_detail
                })
        except ClientError as err:
            print(f"Error fetching IAM: {err}")
        return iam_data