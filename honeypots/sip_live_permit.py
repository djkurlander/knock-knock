#!/usr/bin/env python3
"""One-shot SIP live-call permit helpers."""

import json
import os
import re

import redis


DEFAULT_TTL_SECONDS = 24 * 60 * 60
MAX_TTL_SECONDS = int(os.environ.get('SIP_LIVE_PERMIT_MAX_TTL', str(2 * 24 * 60 * 60)))
DEFAULT_MAX_SECONDS = 45
MAX_CALL_SECONDS_CAP = int(os.environ.get('SIP_LIVE_MAX_CALL_SECONDS_CAP', '90'))
KEY_PREFIX = os.environ.get('SIP_LIVE_PERMIT_PREFIX', 'knock:sip:live-permit')
ACTIVE_KEY = os.environ.get('SIP_LIVE_ACTIVE_KEY', 'knock:sip:live-active')
E164_RE = re.compile(r'^\+[1-9]\d{1,14}$')


def redis_client():
    return redis.Redis(
        host=os.environ.get('REDIS_HOST', 'localhost'),
        port=int(os.environ.get('REDIS_PORT', '6379')),
        db=int(os.environ.get('REDIS_DB', '0')),
        decode_responses=True,
    )


def require_e164(number):
    """Return a strict E.164 number, or raise ValueError."""
    value = (number or '').strip()
    if not E164_RE.fullmatch(value):
        raise ValueError('dial number must be strict E.164, e.g. +442039960320')
    return value


def permit_source_ip(source_ip):
    source_ip = (source_ip or '').strip()
    if not source_ip:
        raise ValueError('source IP is required')
    return source_ip


def permit_key(source_ip, dial_number):
    return f'{KEY_PREFIX}:{permit_source_ip(source_ip)}:{require_e164(dial_number)}'


def clamp_ttl(ttl_seconds):
    ttl = int(ttl_seconds if ttl_seconds is not None else DEFAULT_TTL_SECONDS)
    if ttl <= 0:
        raise ValueError('ttl must be positive')
    return min(ttl, MAX_TTL_SECONDS)


def clamp_max_seconds(max_seconds):
    seconds = int(max_seconds if max_seconds is not None else DEFAULT_MAX_SECONDS)
    if seconds <= 0:
        raise ValueError('max seconds must be positive')
    return min(seconds, MAX_CALL_SECONDS_CAP)


def make_permit(source_ip, dial_number, *, permit_id, max_seconds=None, note=''):
    if not permit_id:
        raise ValueError('permit_id is required')
    dial_number = require_e164(dial_number)
    return {
        'permit_id': str(permit_id),
        'source_ip': permit_source_ip(source_ip),
        'dial_number': dial_number,
        'max_seconds': clamp_max_seconds(max_seconds),
        'note': str(note or ''),
    }


def create_permit(client, permit, ttl_seconds=None):
    ttl = clamp_ttl(ttl_seconds)
    key = permit_key(permit['source_ip'], permit['dial_number'])
    client.set(key, json.dumps(permit, sort_keys=True), ex=ttl)
    return key, ttl


def list_permits(client):
    pattern = f'{KEY_PREFIX}:*'
    for key in sorted(client.scan_iter(match=pattern)):
        value = client.get(key)
        ttl = client.ttl(key)
        try:
            permit = json.loads(value) if value else {}
        except Exception:
            permit = {'raw': value}
        yield key, ttl, permit


def delete_permit(client, source_ip, dial_number):
    return client.delete(permit_key(source_ip, dial_number))


def release_active_lock(client, bridge_id):
    script = """
if redis.call('GET', KEYS[1]) == ARGV[1] then
  return redis.call('DEL', KEYS[1])
end
return 0
"""
    return bool(client.eval(script, 1, ACTIVE_KEY, bridge_id))


def consume_permit_and_acquire_live(client, source_ip, dial_number, bridge_id):
    """Atomically consume an exact or wildcard permit and acquire the live-call lock."""
    exact_key = permit_key(source_ip, dial_number)
    wildcard_key = permit_key('*', dial_number)
    script = """
local permit = redis.call('GET', KEYS[1])
local permit_key = KEYS[1]
if not permit then
  permit = redis.call('GET', KEYS[2])
  permit_key = KEYS[2]
end
if not permit then
  return nil
end
if redis.call('EXISTS', KEYS[3]) == 1 then
  return false
end
redis.call('DEL', permit_key)
redis.call('SET', KEYS[3], ARGV[1], 'EX', ARGV[2])
return {permit, permit_key}
"""
    # Use the configured cap for the provisional lock. The exact call duration
    # from the permit is parsed below, but this keeps the consume path atomic.
    lock_ttl = max(5, MAX_CALL_SECONDS_CAP + 10)
    result = client.eval(script, 3, exact_key, wildcard_key, ACTIVE_KEY, bridge_id, lock_ttl)
    if not result:
        return None
    value, consumed_key = result
    try:
        permit = json.loads(value)
    except Exception:
        release_active_lock(client, bridge_id)
        return None
    permit['permit_key'] = consumed_key
    permit['max_seconds'] = clamp_max_seconds(permit.get('max_seconds'))
    client.expire(ACTIVE_KEY, max(5, permit['max_seconds'] + 10))
    return permit
