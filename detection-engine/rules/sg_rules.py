def evaluate_sg_open_to_world(sg_data):
    findings = []
    for sg in sg_data:
        group_id = sg.get("GroupId")
        group_name = sg.get("GroupName", "unknown")
        
        for permission in sg.get("IpPermissions", []):
            # Check for 0.0.0.0/0 (IPv4) or ::/0 (IPv6) open ingress
            ip_ranges = [ip.get("CidrIp") for ip in permission.get("IpRanges", [])]
            ipv6_ranges = [ip.get("CidrIpv6") for ip in permission.get("Ipv6Ranges", [])]
            
            if "0.0.0.0/0" in ip_ranges or "::/0" in ipv6_ranges:
                from_port = permission.get("FromPort", "All")
                to_port = permission.get("ToPort", "All")
                findings.append({
                    "rule_id": "SG_OPEN_TO_WORLD",
                    "severity_raw": "HIGH",
                    "resource": {
                        "type": "AWS::EC2::SecurityGroup",
                        "id": group_id,
                        "arn": f"arn:aws:ec2:::security-group/{group_id}"
                    },
                    "status": "FAIL",
                    "risk_score": 0,
                    "score_breakdown": [],
                    "explanation": "",
                    "compliance_mappings": []
                })
                break  # Flag once per open security group
    return findings