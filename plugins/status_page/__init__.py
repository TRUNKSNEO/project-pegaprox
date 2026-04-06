"""
Public Status Page Plugin — Cluster health for monitoring screens
NS: Apr 2026

Public endpoint with URL auth key, no login required.
Designed for IT monitoring dashboards (like PRTG status pages).
"""
import os
import json
import hmac
import logging
import uuid
from flask import request, jsonify, send_file

from pegaprox.api.plugins import register_plugin_route
from pegaprox.globals import cluster_managers

PLUGIN_NAME = "Public Status Page"
PLUGIN_DIR = os.path.dirname(os.path.abspath(__file__))

def _load_config():
    cfg_path = os.path.join(PLUGIN_DIR, 'config.json')
    try:
        with open(cfg_path) as f:
            return json.load(f)
    except Exception:
        return {"auth_key": "", "refresh_interval": 30}

def _save_config(cfg):
    cfg_path = os.path.join(PLUGIN_DIR, 'config.json')
    with open(cfg_path, 'w') as f:
        json.dump(cfg, f, indent=4)


def _check_key():
    """Validate URL auth key — returns error tuple or None if OK"""
    cfg = _load_config()
    expected = cfg.get('auth_key', '')
    if not expected:
        return {'error': 'Status page not configured. Set an auth key in plugin settings.'}, 403
    key = request.args.get('key', '')
    if not hmac.compare_digest(key, expected):
        return {'error': 'Invalid or missing auth key'}, 401
    return None


def _require_admin():
    """Check if current user is admin — returns error tuple or None"""
    from pegaprox.utils.auth import load_users
    from pegaprox.models.permissions import ROLE_ADMIN
    username = request.session.get('user', '')
    users = load_users()
    user = users.get(username, {})
    if user.get('role') != ROLE_ADMIN:
        return {'error': 'Admin access required'}, 403
    return None


def _get_config():
    """Return full config including auth key (admin only)"""
    err = _require_admin()
    if err:
        return err
    cfg = _load_config()
    return {
        'auth_key': cfg.get('auth_key', ''),
        'page_title': cfg.get('page_title', 'System Status'),
        'refresh_interval': cfg.get('refresh_interval', 30),
        'show_node_details': cfg.get('show_node_details', True),
        'show_vm_summary': cfg.get('show_vm_summary', True),
        'show_storage': cfg.get('show_storage', True),
        'show_cluster_name': cfg.get('show_cluster_name', True),
        'theme_color': cfg.get('theme_color', '#e57000'),
        'custom_logo_url': cfg.get('custom_logo_url', ''),
        'status_url': f"/status?key={cfg.get('auth_key', '')}",
    }


def _update_config():
    """Update config (admin only)"""
    err = _require_admin()
    if err:
        return err
    data = request.get_json() or {}
    cfg = _load_config()
    for k in ['page_title', 'refresh_interval', 'show_node_details', 'show_vm_summary',
              'show_storage', 'show_cluster_name', 'theme_color', 'custom_logo_url']:
        if k in data:
            cfg[k] = data[k]
    _save_config(cfg)
    return {'success': True}


def _generate_key():
    """Generate a new auth key (admin only)"""
    err = _require_admin()
    if err:
        return err
    cfg = _load_config()
    cfg['auth_key'] = uuid.uuid4().hex[:24]
    _save_config(cfg)
    logging.info(f"[PLUGINS] Status page auth key regenerated")
    return {'success': True, 'auth_key': cfg['auth_key']}


def _public_status():
    """Public health endpoint — validated by URL key, no session needed.
    This is called directly, NOT through the plugin proxy (which requires auth).
    """
    err = _check_key()
    if err:
        return err

    cfg = _load_config()
    clusters = []

    for cid, mgr in cluster_managers.items():
        cluster_info = {
            'id': cid,
            'name': mgr.config.name if cfg.get('show_cluster_name', True) else 'Cluster',
            'connected': mgr.is_connected,
            'nodes': [],
            'vm_summary': {},
            'storage': [],
        }

        if not mgr.is_connected:
            cluster_info['status'] = 'offline'
            clusters.append(cluster_info)
            continue

        cluster_info['status'] = 'online'

        # node health
        if cfg.get('show_node_details', True):
            try:
                node_status = mgr.get_node_status()
                for name, info in (node_status or {}).items():
                    cluster_info['nodes'].append({
                        'name': name,
                        'online': not info.get('offline', False),
                        'cpu_percent': round(info.get('cpu_percent', 0), 1),
                        'mem_percent': round(info.get('mem_percent', 0), 1),
                        'uptime': info.get('uptime', 0),
                    })
            except Exception:
                pass

        # VM summary
        if cfg.get('show_vm_summary', True):
            try:
                vms = mgr.get_vm_resources()
                running = sum(1 for v in vms if v.get('status') == 'running')
                stopped = sum(1 for v in vms if v.get('status') == 'stopped')
                total = len(vms)
                qemu = sum(1 for v in vms if v.get('type') == 'qemu')
                lxc = sum(1 for v in vms if v.get('type') == 'lxc')
                cluster_info['vm_summary'] = {
                    'total': total, 'running': running, 'stopped': stopped,
                    'qemu': qemu, 'lxc': lxc,
                }
            except Exception:
                pass

        # storage (aggregate per cluster, no per-node breakdown)
        if cfg.get('show_storage', True):
            try:
                # get storage from first online node
                for n in (cluster_info['nodes'] or [{'name': ''}]):
                    if not n.get('online', True):
                        continue
                    node_name = n['name']
                    if not node_name:
                        continue
                    storages = mgr.get_storage_list(node_name)
                    seen = set()
                    for s in (storages or []):
                        sid = s.get('storage', '')
                        if sid in seen:
                            continue
                        seen.add(sid)
                        total_bytes = s.get('total', 0)
                        used_bytes = s.get('used', 0)
                        if total_bytes > 0:
                            cluster_info['storage'].append({
                                'name': sid,
                                'type': s.get('type', ''),
                                'total': total_bytes,
                                'used': used_bytes,
                                'percent': round(used_bytes / total_bytes * 100, 1),
                            })
                    break  # one node is enough for shared storage
            except Exception:
                pass

        clusters.append(cluster_info)

    return {'clusters': clusters, 'config': {
        'page_title': cfg.get('page_title', 'System Status'),
        'refresh_interval': cfg.get('refresh_interval', 30),
        'show_node_details': cfg.get('show_node_details', True),
        'show_vm_summary': cfg.get('show_vm_summary', True),
        'show_storage': cfg.get('show_storage', True),
        'theme_color': cfg.get('theme_color', '#e57000'),
        'custom_logo_url': cfg.get('custom_logo_url', ''),
    }}


def register(app):
    """Register plugin routes"""
    # Admin routes (through plugin proxy, requires auth)
    register_plugin_route('status_page', 'config', _get_config)
    register_plugin_route('status_page', 'config/update', _update_config)
    register_plugin_route('status_page', 'generate-key', _generate_key)

    # Public data route — also registered through plugin proxy for the JSON API
    # but the actual public access bypasses auth (see _public_status_endpoint in settings.py)
    register_plugin_route('status_page', 'public', _public_status)

    logging.info("[PLUGINS] Public Status Page plugin registered")
