## pfsense-mullvad-rotator
Tool for randomly rotating Mullvad WireGuard servers within pfSense, with support for key rotation.

```
usage: rotate.py [-h] --url URL --api-key API_KEY [--filter FILTER] [--gateway GATEWAY] [--mullvad-device MULLVAD_DEVICE]
                 [--mullvad-account MULLVAD_ACCOUNT] [--no-verify] [--tunnel TUNNEL]

options:
  -h, --help            show this help message and exit
  --url URL             pfSense base URL
  --api-key API_KEY     pfSense REST API key [env var: API_KEY]
  --filter FILTER       Lambda function for filtering candidate servers (dicts). Fields are the same as in
                        https://api.mullvad.net/www/relays/wireguard. Passing the server object to the ping() function will return its
                        latency (measured through --gateway) in milliseconds. E.g.: --filter "server['owned'] and ping(server) < 100"
  --gateway GATEWAY     WAN gateway name. Used for creating static routes, measuring server pings and sending Mullvad API requests
  --mullvad-device MULLVAD_DEVICE
                        Mullvad device name. Used for WireGuard key rotation
  --mullvad-account MULLVAD_ACCOUNT
                        Mullvad account number. Enables WireGuard key rotation [env var: MULLVAD_ACCOUNT]
  --no-verify           Disable certificate checking for pfSense
  --tunnel TUNNEL       WireGuard tunnel name
```

## Usage (Docker)
1. Install [pfSense REST API](https://pfrest.org/INSTALL_AND_CONFIG/) and create an API key under System/REST API/Keys
2. Create a new Mullvad device under https://mullvad.net/en/account/wireguard-config and take note of the name
3. Create a cronjob: `0 0 * * * API_KEY="your_pfsense_api_key" MULLVAD_ACCOUNT="your_mullvad_account_number" docker run --rm -t -e API_KEY -e MULLVAD_ACCOUNT tcrinky/pfsense-mullvad-rotator --url "https://your_pfsense_host" --no-verify --mullvad-device "your_mullvad_device_name" --filter "ping(server) < 100"`
