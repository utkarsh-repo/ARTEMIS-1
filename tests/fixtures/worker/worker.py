"""Tiny deterministic worker used only by ARTEMIS real-runtime integration tests."""
import json
import os
import socket
import sys
import time


def network_probe(address, family):
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(0.35)
    try:
        sock.connect((address, 80))
        return False
    except OSError:
        return True
    finally:
        sock.close()


def probe():
    status = {}
    with open('/proc/self/status', encoding='ascii') as handle:
        lines = handle.read().splitlines()
    status['uid'] = os.geteuid()
    status['cap_eff'] = int(next(line.split()[1] for line in lines if line.startswith('CapEff:')), 16)
    status['no_new_privs'] = next(line.split()[1] for line in lines if line.startswith('NoNewPrivs:')) == '1'
    try:
        with open('/artemis-rootfs-write-probe', 'w', encoding='ascii') as handle:
            handle.write('unexpected')
        status['rootfs_read_only'] = False
    except OSError:
        status['rootfs_read_only'] = True
    with open('/tmp/artemis-tmpfs-probe', 'w', encoding='ascii') as handle:
        handle.write('ok')
    status['tmpfs_writable'] = True
    for key, filename in [('memory_max', '/sys/fs/cgroup/memory.max'), ('cpu_max', '/sys/fs/cgroup/cpu.max'), ('pids_max', '/sys/fs/cgroup/pids.max')]:
        try:
            with open(filename, encoding='ascii') as handle:
                status[key] = handle.read().strip()
        except OSError:
            status[key] = None
    status['ipv4_direct_socket_blocked'] = network_probe('192.0.2.1', socket.AF_INET)
    try:
        status['ipv6_direct_socket_blocked'] = network_probe('2001:db8::1', socket.AF_INET6)
    except OSError:
        status['ipv6_direct_socket_blocked'] = True
    return status


payload = json.loads(sys.stdin.read())
mode = payload.get('mode', 'probe')
if mode == 'sleep':
    time.sleep(min(float(payload.get('seconds', 30)), 120.0))
    result = {'slept': True}
elif mode == 'probe':
    result = probe()
else:
    # External task content cannot choose a command or module to execute.
    print(json.dumps({'schema_version': 1, 'status': 'failed', 'result': {}, 'evidence': []}))
    raise SystemExit(2)
print(json.dumps({'schema_version': 1, 'status': 'completed', 'result': result,
                  'evidence': ['runtime-probe-v1']}), flush=True)
