from concurrent.futures import ThreadPoolExecutor
from time import time, sleep
import json
import re
import secrets
import shlex
import sys

from configargparse import ArgumentParser
import httpx

def shell(cmd: str, error=True) -> str:
    data = pf.post('/api/v2/diagnostics/command_prompt',
                   json={'command': cmd}
                   ).json()['data']
    if error:
        assert data['result_code'] == 0
    return data['output'].strip()

# measure server ping through WAN to circumvent overhead of current tunnel (if any)
def ping(server: dict, n=1):
    cmd = shlex.join(['ping', '-S', wan_ip, '-c', str(n), '--', server['ipv4_addr_in']])
    output = shell(cmd, error=False)
    avg = re.search(r'= [\d\.]+/([\d\.]+)/', output)
    return float(avg.group(1)) if avg else 100000

def block_until_applied(path: str, timeout=120.0):
    pf.post(path).raise_for_status()
    start = time()
    while True:
        assert start - time() < timeout
        resp = pf.get(path)
        if resp.json()['data']['applied']:
            return True
        sleep(1/4)

def rotate_mullvad_wireguard_key():
    # authenticate with mullvad
    cmd = shlex.join([*curl_args,
                      '-X', 'POST',
                      '-H', 'Content-Type: application/json',
                      '-d', json.dumps({'account_number': args.mullvad_account}),
                      'https://api.mullvad.net/auth/v1/token'])
    token = json.loads(shell(cmd))['access_token']
    
    # find mullvad device by name or pubkey
    cmd = shlex.join([*curl_args,
                      '-H', f'Authorization: Bearer {token}',
                      'https://api.mullvad.net/accounts/v1/devices'])
    devices = json.loads(shell(cmd))
    device = next((d for d in devices if d['name'] == args.mullvad_device), None)
    if not device:
        print('--mullvad-device is invalid', file=sys.stderr)
        sys.exit(1)

    private_key = shell('wg genkey')
    public_key = shell(f'echo {shlex.quote(private_key)} | wg pubkey')

    # update mullvad device pubkey, fetch new internal ip
    cmd = shlex.join([*curl_args,
                      '-X', 'PUT',
                      '-H', f'Authorization: Bearer {token}',
                      '-H', 'Content-Type: application/json',
                      '-d', json.dumps({'pubkey': public_key}),
                      f'https://api.mullvad.net/accounts/v1/devices/{device['id']}/pubkey'])
    assigned_ip = json.loads(shell(cmd))['ipv4_address'].split('/')[0]

    # assign ip to wireguard interface
    pf.patch('/api/v2/interface',
             json={'id': wg_interface['id'],
                   'ipaddr': assigned_ip,
                   'subnet': 32}
            ).raise_for_status()
    block_until_applied('/api/v2/interface/apply')

    # assign privkey to wireguard tunnel
    pf.patch('/api/v2/vpn/wireguard/tunnel',
             json={'id': wg_tunnel['id'],
                   'privatekey': private_key}
            ).raise_for_status()
    block_until_applied('/api/v2/vpn/wireguard/apply')

def update_reserved_static_route(server: dict):
    keyword = f'auto: {args.tunnel}'
    upsert = {'network': f'{server['ipv4_addr_in']}/32',
              'gateway': args.gateway,
              'descr': f'{server['hostname']} ({keyword})',
              'disabled': False}

    routes = pf.get('/api/v2/routing/static_routes').json()['data']
    reserved = next((r for r in routes if keyword in r['descr']), None)
    if reserved:
        upsert['id'] = reserved['id']
        
    pf.request(method='PATCH' if reserved else 'POST',
               url='/api/v2/routing/static_route',
               json=upsert
               ).raise_for_status()

    block_until_applied('/api/v2/routing/apply')

def update_reserved_wireguard_peer(server: dict, server2: dict = None):
    upsert = {'enabled': True,
              'tun': args.tunnel,
              'endpoint': server['ipv4_addr_in'],
              'port': str(server2['multihop_port'] if server2 else args.port),
              'descr': f'{server['hostname']}'
                       f'{':'+server2['hostname'] if server2 else ''} '
                       '(auto)',
              'publickey': server2['pubkey'] if server2 else server['pubkey'],
              'allowedips': [{'address': '0.0.0.0', 'mask': 0}]}
    
    peers = [p for p in pf.get('/api/v2/vpn/wireguard/peers').json()['data']
             if p['tun'] == args.tunnel]
    
    reserved = next((p for p in peers if '(auto)' in p['descr']), None)
    if reserved:
        upsert['id'] = reserved['id']
        
    pf.request(method='PATCH' if reserved else 'POST',
               url='/api/v2/vpn/wireguard/peer',
               json=upsert
               ).raise_for_status()

    # disable any other active peers
    for peer in peers:
        if peer != reserved and peer['enabled']:
            pf.patch('/api/v2/vpn/wireguard/peer',
                     json={'id': peer['id'],
                           'enabled': False}
                     ).raise_for_status()

    block_until_applied('/api/v2/vpn/wireguard/apply')

def pick_server():
    if not servers:
        print('no matching servers. try broadening your filter', file=sys.stderr)
        sys.exit(1)
    # ensure odds are equal between countries regardless of number of servers
    country = secrets.choice(list({s['country_code'] for s in servers}))
    server = secrets.choice([s for s in servers if s['country_code'] == country])
    servers.remove(server)
    return server

if __name__ == '__main__':
    arg_parser = ArgumentParser()
    arg_parser.add_argument('--url',
                            required=True,
                            help='pfSense base URL')
    arg_parser.add_argument('--api-key',
                            env_var='API_KEY',
                            required=True,
                            help='pfSense REST API key')
    arg_parser.add_argument('--filter',
                            type=lambda code: eval(f'lambda server: {code}'),
                            help='Lambda function for filtering candidate servers (dicts). '
                                 'Follows format of https://api.mullvad.net/www/relays/wireguard. '
                                 'Passing the server object to the ping() function will return its latency in milliseconds (measured through --gateway). '
                                 'E.g.: --filter "server[\'owned\'] and ping(server) < 100"')
    arg_parser.add_argument('--gateway',
                            default='WAN_DHCP',
                            help='Upstream gateway name. Used for static routes, ping packets and Mullvad API requests')
    arg_parser.add_argument('--mullvad-device',
                            type=str.lower,
                            help='Mullvad device name. Used for WireGuard key rotation')
    arg_parser.add_argument('--mullvad-account',
                            env_var='MULLVAD_ACCOUNT',
                            help='Mullvad account number. Enables WireGuard key rotation')
    arg_parser.add_argument('--multihop',
                            action='store_true',
                            help='Pick a second server to be used as exit node. '
                                 'Be advised: Traffic between servers may still be correlated by an adversary: https://www.reddit.com/r/mullvadvpn/comments/1hujzcr. '
                                 'As an alternative, you can set up a second WireGuard tunnel and use --gateway to route another tunnel through it')
    arg_parser.add_argument('--no-verify',
                            action='store_true',
                            help='Disable certificate checking for pfSense')
    arg_parser.add_argument('--port',
                            type=int,
                            default=51820,
                            help='WireGuard peer port. Not compatible with --multihop. '
                                 'Valid ranges: 53, 123, 4000-33433, 33565-51820, 52001-60000')
    arg_parser.add_argument('--tunnel',
                            default='tun_wg0',
                            help='WireGuard tunnel name')
    args = arg_parser.parse_args()

    if args.mullvad_account and not args.mullvad_device:
        print('--mullvad-device is required when key rotation is enabled', file=sys.stderr)
        sys.exit(1)

    pf = httpx.Client(base_url=args.url,
                      headers={'x-api-key': args.api_key},
                      verify=(not args.no_verify),
                      timeout=60)
    
    try:
        wg_tunnel = next(t for t in pf.get('/api/v2/vpn/wireguard/tunnels').json()['data']
                         if t['name'] == args.tunnel)
        wg_interface = next(i for i in pf.get('/api/v2/interfaces').json()['data']
                            if i['if'] == args.tunnel)
        wan_gateway = next(g for g in pf.get('/api/v2/routing/gateways').json()['data']
                           if g['name'] == args.gateway)
        wan_interface = next(i for i in pf.get('/api/v2/interfaces').json()['data']
                             if i['id'] == wan_gateway['interface'])
        wan_ip = shell("ifconfig -- %s | grep 'inet ' | awk '{print $2}'" % shlex.quote(wan_interface['if']))
    except StopIteration:
        print(f'--gateway and/or --tunnel are invalid', file=sys.stderr)
        sys.exit(1)

    # send internet-facing requests directly via the pfSense host and WAN
    # this circumvents scenarios where the mullvad API can't be reached because the client is behind a downed tunnel
    ip = shell(shlex.join(['dig', '@194.242.2.2', 'api.mullvad.net',
                           '+short', '+https', '+tls-hostname=dns.mullvad.net', '-b', wan_ip]) + ' | head -n 1')
    curl_args = ['curl',
                 '--silent',
                 '--fail',
                 '--interface', wan_ip,
                 '--resolve', f'api.mullvad.net:443:{ip}']

    if args.mullvad_account:
        print('rotating mullvad wireguard key ..')
        rotate_mullvad_wireguard_key()

    print('fetching server list ..')           
    servers = json.loads(shell(shlex.join([*curl_args, 'https://api.mullvad.net/www/relays/wireguard'])))
    servers = [s for s in servers if s.get('active')]

    if args.filter:
        print('filtering server list ..')
        with ThreadPoolExecutor(max_workers=50) as pool:
            for server, ok in list(zip(servers, pool.map(args.filter, servers))):
                if not ok:
                    servers.remove(server)

    server = pick_server()
    print(f'picked server: {server['hostname']}')

    # pick second server to be used as exit node
    server2 = pick_server() if args.multihop else None
    if server2:
        print(f'picked server #2: {server2['hostname']}')

    print('configuring static route ..')
    update_reserved_static_route(server)

    print('configuring wireguard peer ..')
    update_reserved_wireguard_peer(server, server2)  
