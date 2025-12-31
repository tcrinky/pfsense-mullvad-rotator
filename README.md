## pfsense-mullvad-rotator
Tool for randomly rotating Mullvad WireGuard servers within pfSense, with support for key rotation.

```
usage: rotate.py [-h] --url URL --api-key API_KEY [--filter FILTER] [--gateway GATEWAY]
                 [--mullvad-device MULLVAD_DEVICE] [--mullvad-account MULLVAD_ACCOUNT] [--multihop]
                 [--no-verify] [--port PORT] [--tunnel TUNNEL]

options:
  -h, --help            show this help message and exit
  --url URL             pfSense base URL
  --api-key API_KEY     pfSense REST API key [env var: API_KEY]
  --filter FILTER       Lambda function for filtering candidate servers (dicts). Follows format of
                        https://api.mullvad.net/www/relays/wireguard. Passing the server object to the ping()   
                        function will return its latency in milliseconds (measured through --gateway). E.g.:    
                        --filter "server['owned'] and ping(server) < 100"
  --gateway GATEWAY     Upstream gateway name. Used for static routes, ping packets and Mullvad API requests    
  --mullvad-device MULLVAD_DEVICE
                        Mullvad device name. Used for WireGuard key rotation
  --mullvad-account MULLVAD_ACCOUNT
                        Mullvad account number. Enables WireGuard key rotation [env var: MULLVAD_ACCOUNT]       
  --multihop            Pick a second server to be used as exit node. Be advised: Traffic between servers may   
                        still be correlated by an adversary:
                        https://www.reddit.com/r/mullvadvpn/comments/1hujzcr. As an alternative, you can set    
                        up a second WireGuard tunnel and use --gateway to route another tunnel through it       
  --no-verify           Disable certificate checking for pfSense
  --port PORT           WireGuard peer port. Not compatible with --multihop. Valid ranges: 53, 123,
                        4000-33433, 33565-51820, 52001-60000
  --tunnel TUNNEL       WireGuard tunnel name
```

## Usage (Docker)
1. Install [pfSense REST API](https://pfrest.org/INSTALL_AND_CONFIG/) and create an API key under System/REST API/Keys
1. Set up a WireGuard tunnel using the guide at https://mullvad.net/en/help/pfsense-with-wireguard
1. Find the device corresponding to your public key at https://mullvad.net/en/account/devices
1. Create a cronjob:
   ```bash
   0 0 * * * API_KEY="your_pfsense_api_key" MULLVAD_ACCOUNT="your_mullvad_account_number" docker run --rm -e API_KEY -e MULLVAD_ACCOUNT tcrinky/pfsense-mullvad-rotator --no-verify --url "https://your_pfsense_host" --mullvad-device "your_mullvad_device_name" --filter "ping(server) < 100"
   ```
