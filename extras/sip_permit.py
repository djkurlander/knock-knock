#!/usr/bin/env python3
"""Create and inspect one-shot SIP live-call permits."""

import argparse
import os
import sys
import time


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'honeypots'))

import sip_live_permit  # noqa: E402


def _fmt_ttl(ttl):
    if ttl is None or ttl < 0:
        return 'no-expiry'
    if ttl < 120:
        return f'{ttl}s'
    if ttl < 48 * 3600:
        return f'{ttl / 3600:.1f}h'
    return f'{ttl / 86400:.1f}d'


def _fmt_expires_at(ttl):
    if ttl is None or ttl < 0:
        return 'no-expiry'
    return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(time.time() + ttl))


def cmd_create(args):
    client = sip_live_permit.redis_client()
    permit_id = args.permit_id or f'manual-{time.strftime("%Y%m%d-%H%M%S")}'
    ttl = args.ttl
    if args.hours is not None:
        ttl = int(args.hours * 3600)
    permit = sip_live_permit.make_permit(
        args.source_ip,
        args.dial_number,
        permit_id=permit_id,
        max_seconds=args.max_seconds,
        note=args.note,
    )
    key, actual_ttl = sip_live_permit.create_permit(client, permit, ttl)
    print(f'created {key}')
    print(f'permit_id={permit["permit_id"]}')
    print(f'dial_number={permit["dial_number"]}')
    print(f'max_seconds={permit["max_seconds"]}')
    print(f'ttl={actual_ttl}s')


def cmd_list(_args):
    client = sip_live_permit.redis_client()
    found = False
    for key, ttl, permit in sip_live_permit.list_permits(client):
        found = True
        print(
            f'{key} ttl={_fmt_ttl(ttl)} '
            f'expires_at={_fmt_expires_at(ttl)} '
            f'permit_id={permit.get("permit_id", "")} '
            f'source_ip={permit.get("source_ip", "")} '
            f'dial_number={permit.get("dial_number", "")} '
            f'max_seconds={permit.get("max_seconds", "")} '
            f'note={permit.get("note", "")}'
        )
    if not found:
        print('no SIP live permits')


def cmd_delete(args):
    client = sip_live_permit.redis_client()
    deleted = sip_live_permit.delete_permit(client, args.source_ip, args.dial_number)
    print(f'deleted={deleted}')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='cmd', required=True)

    create = sub.add_parser('create', help='create a one-shot exact IP/phone permit')
    create.add_argument('source_ip', help='exact source IP, or * for any source IP targeting this number')
    create.add_argument('dial_number', help='strict E.164 number, e.g. +442039960320')
    create.add_argument('--permit-id')
    create.add_argument('--ttl', type=int, default=sip_live_permit.DEFAULT_TTL_SECONDS, help='TTL in seconds')
    create.add_argument('--hours', type=float, help='TTL in hours; overrides --ttl')
    create.add_argument('--max-seconds', type=int, default=sip_live_permit.DEFAULT_MAX_SECONDS)
    create.add_argument('--note', default='')
    create.set_defaults(func=cmd_create)

    list_cmd = sub.add_parser('list', help='list pending permits')
    list_cmd.set_defaults(func=cmd_list)

    delete = sub.add_parser('delete', help='delete one exact IP/phone permit')
    delete.add_argument('source_ip', help='exact source IP, or * for a wildcard permit')
    delete.add_argument('dial_number')
    delete.set_defaults(func=cmd_delete)

    args = parser.parse_args(argv)
    args.func(args)


if __name__ == '__main__':
    main()
