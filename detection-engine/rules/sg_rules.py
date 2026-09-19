from .common import new_finding, PROD_NAME_HINTS


def evaluate_sg_open_to_world(sg_data, scan_id):
    """SG_OPEN_TO_WORLD.

    CHANGED FROM ORIGINAL: now collects `open_cidrs` and `exposed_ports` as
    actual lists (previously nothing was reported beyond the bare
    detection), so P2's `sensitive_port` factor and derived
    `first_sensitive_port`/`first_sensitive_service` signals have real data
    to work with. `attached_to_prod` is a name/description heuristic on the
    security group itself (same spirit as P2's own name-based derived
    signals) since correlating to an attached instance's tags would need an
    extra describe_instances call this connector does not make.
    """
    findings = []
    for sg in sg_data:
        group_id = sg.get("GroupId")
        group_name = sg.get("GroupName", "unknown")
        description = sg.get("Description", "")
        name_lower = f"{group_name} {description}".lower()
        attached_to_prod = any(hint in name_lower for hint in PROD_NAME_HINTS)

        open_cidrs = set()
        exposed_ports = set()
        any_open = False

        for permission in sg.get("IpPermissions", []):
            ip_ranges = [ip.get("CidrIp") for ip in permission.get("IpRanges", [])]
            ipv6_ranges = [ip.get("CidrIpv6") for ip in permission.get("Ipv6Ranges", [])]

            is_open = "0.0.0.0/0" in ip_ranges or "::/0" in ipv6_ranges
            if is_open:
                any_open = True
                if "0.0.0.0/0" in ip_ranges:
                    open_cidrs.add("0.0.0.0/0")
                if "::/0" in ipv6_ranges:
                    open_cidrs.add("::/0")

                from_port = permission.get("FromPort")
                to_port = permission.get("ToPort")
                if from_port is not None and to_port is not None:
                    # Cap the expanded range so a "-1 to 65535 / all traffic"
                    # rule doesn't blow up the ports list; sensitive-port
                    # matching only needs the well-known ports anyway.
                    span = range(max(from_port, 0), min(to_port, 65535) + 1)
                    if len(span) <= 1024:
                        exposed_ports.update(span)
                    else:
                        exposed_ports.add(from_port)

        if any_open:
            findings.append(new_finding(
                rule_id="SG_OPEN_TO_WORLD",
                scan_id=scan_id,
                severity_raw="high",
                resource_type="security_group",
                resource_id=f"arn:aws:ec2:::security-group/{group_id}",
                resource_name=group_name,
                region="unknown",  # connector does not currently capture SG region separately
                context={
                    "open_cidrs": sorted(open_cidrs),
                    "exposed_ports": sorted(exposed_ports),
                    "attached_to_prod": attached_to_prod,
                },
            ))
    return findings
