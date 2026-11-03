#!/usr/bin/env python3
"""Safely upsert Azure Front Door DNS validation records in Route 53.

Authentication: use the AWS SDK default credential chain. The Azure DevOps
pipeline should provide short-lived credentials from an assumed IAM role.

Usage:
  python route53_manager.py UPSERT example.com _dnsauth.example.com TXT token --dry-run
  python route53_manager.py UPSERT example.com _dnsauth.example.com TXT token

Use --hosted-zone-id Z... to pin the target zone. For production, configure
APPROVED_HOSTED_ZONE_IDS (comma-separated) and/or APPROVED_DNS_SUFFIXES.
"""

import argparse
import logging
import os
import sys
from typing import Optional

import boto3
from botocore.exceptions import BotoCoreError, ClientError, WaiterError

LOG = logging.getLogger("route53_manager")


def dns_name(value: str) -> str:
    name = value.strip().rstrip(".").lower()
    if not name or len(name) > 253 or any(not part or len(part) > 63 for part in name.split(".")):
        raise ValueError(f"Invalid DNS name: {value!r}")
    if any(not all(c.isascii() and (c.isalnum() or c in '-_') for c in part) for part in name.split('.')):
        raise ValueError(f"Invalid DNS name: {value!r}")
    return name


def is_within(name: str, suffix: str) -> bool:
    return name == suffix or name.endswith("." + suffix)


def zone_id_only(value: str) -> str:
    return value.rsplit("/", 1)[-1]


def approved_ids() -> set[str]:
    return {zone_id_only(x.strip()) for x in os.getenv("APPROVED_HOSTED_ZONE_IDS", "").split(",") if x.strip()}


def approved_suffixes() -> list[str]:
    return [dns_name(x) for x in os.getenv("APPROVED_DNS_SUFFIXES", "").split(",") if x.strip()]


def find_hosted_zone(client, fqdn: str, record_name: str, explicit_id: Optional[str] = None) -> tuple[str, str]:
    candidates = []
    allowed_ids = approved_ids()
    for page in client.get_paginator("list_hosted_zones").paginate():
        for zone in page["HostedZones"]:
            zid = zone_id_only(zone["Id"])
            name = dns_name(zone["Name"])
            if zone.get("Config", {}).get("PrivateZone", False):
                continue
            if explicit_id and zid != explicit_id:
                continue
            if allowed_ids and zid not in allowed_ids:
                continue
            if is_within(fqdn, name) and is_within(record_name, name):
                candidates.append((zid, name))

    if not candidates:
        raise ValueError("No permitted public hosted zone matches the domain and record name")
    longest = max(len(name) for _, name in candidates)
    best = [(zid, name) for zid, name in candidates if len(name) == longest]
    if len(best) != 1:
        raise ValueError("Ambiguous public hosted zones: supply --hosted-zone-id explicitly")
    return best[0]


def existing_record(client, zone_id: str, record_name: str, record_type: str):
    response = client.list_resource_record_sets(
        HostedZoneId=zone_id,
        StartRecordName=record_name + ".",
        StartRecordType=record_type,
        MaxItems="1",
    )
    for record in response.get("ResourceRecordSets", []):
        if dns_name(record["Name"]) == record_name and record["Type"] == record_type:
            return record
    return None


def txt_value(raw: str) -> str:
    # This interface expects one simple Azure validation token, not arbitrary TXT chunks.
    value = raw.strip()
    if not value or '"' in value or "\\" in value or "\n" in value or "\r" in value:
        raise ValueError("TXT value must be a non-empty single token without quotes, backslashes or newlines")
    if len(value.encode("utf-8")) > 255:
        raise ValueError("TXT token exceeds the 255-byte limit for one TXT string")
    return '"' + value + '"'


def desired_records(existing, record_type: str, record_value: str):
    if record_type == "TXT":
        requested = txt_value(record_value)
        if existing:
            if "ResourceRecords" not in existing or existing.get("SetIdentifier"):
                raise ValueError("Complex/alias/routing-policy record cannot be safely modified")
            values = [item["Value"] for item in existing["ResourceRecords"]]
            if requested in values:
                return values, True
            return values + [requested], False
        return [requested], False

    value = dns_name(record_value) + "."
    if existing:
        if "ResourceRecords" not in existing or existing.get("SetIdentifier"):
            raise ValueError("Complex/alias/routing-policy record cannot be safely modified")
        current = [item["Value"] for item in existing["ResourceRecords"]]
        if len(current) != 1:
            raise ValueError("Unexpected CNAME record shape")
        if dns_name(current[0]) == dns_name(value):
            return current, True
        raise ValueError("Existing CNAME differs; refusing to overwrite without manual review")
    return [value], False


def run(args) -> int:
    fqdn = dns_name(args.fqdn)
    record_name = dns_name(args.record_name)
    record_type = args.record_type.upper()
    if record_type not in ("TXT", "CNAME"):
        raise ValueError("Only TXT and CNAME are supported")
    if not is_within(record_name, fqdn):
        raise ValueError("Record name must be within the supplied FQDN")

    suffixes = approved_suffixes()
    if suffixes and not any(is_within(record_name, suffix) for suffix in suffixes):
        raise ValueError("Record name is outside APPROVED_DNS_SUFFIXES")

    client = boto3.client("route53")
    explicit_id = zone_id_only(args.hosted_zone_id) if args.hosted_zone_id else None
    zone_id, zone_name = find_hosted_zone(client, fqdn, record_name, explicit_id)
    LOG.info("Selected public hosted zone %s (%s) for %s", zone_id, zone_name, record_name)

    old = existing_record(client, zone_id, record_name, record_type)
    values, unchanged = desired_records(old, record_type, args.record_value)
    if unchanged:
        LOG.info("Record already contains requested value; no change needed")
        return 0
    if old and old.get("Type") != record_type:
        raise ValueError("Existing record type conflict")
    if args.dry_run:
        LOG.info("DRY RUN: would UPSERT %s %s in %s; existing values preserved", record_name, record_type, zone_id)
        return 0

    response = client.change_resource_record_sets(
        HostedZoneId=zone_id,
        ChangeBatch={
            "Comment": "Azure Front Door validation record managed by pipeline",
            "Changes": [{
                "Action": "UPSERT",
                "ResourceRecordSet": {
                    "Name": record_name + ".",
                    "Type": record_type,
                    "TTL": old.get("TTL", args.ttl) if old else args.ttl,
                    "ResourceRecords": [{"Value": v} for v in values],
                },
            }],
        },
    )
    change_id = response["ChangeInfo"]["Id"]
    LOG.info("Route 53 change submitted: %s", change_id)
    client.get_waiter("resource_record_sets_changed").wait(
        Id=change_id,
        WaiterConfig={"Delay": 10, "MaxAttempts": 60},
    )
    LOG.info("Route 53 change INSYNC: %s", change_id)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Upsert a Route 53 TXT/CNAME validation record")
    parser.add_argument("action", choices=["UPSERT"], help="Only UPSERT is allowed")
    parser.add_argument("fqdn", help="Domain used for hosted zone lookup, e.g. example.com")
    parser.add_argument("record_name", help="Full DNS record name")
    parser.add_argument("record_type", help="TXT or CNAME")
    parser.add_argument("record_value", help="Validation token or CNAME destination")
    parser.add_argument("--hosted-zone-id", help="Explicit approved public hosted zone ID")
    parser.add_argument("--ttl", type=int, default=300, help="TTL for new records (default 300)")
    parser.add_argument("--dry-run", action="store_true", help="Read and validate, but do not update DNS")
    args = parser.parse_args()
    if not 1 <= args.ttl <= 2147483647:
        parser.error("--ttl must be a positive integer")
    try:
        return run(args)
    except (ValueError, ClientError, BotoCoreError, WaiterError) as exc:
        LOG.error("Route 53 operation failed: %s", exc)
        return 1


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
    sys.exit(main())
