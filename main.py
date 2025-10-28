import os
import json

###
### Configuration templates
###

PEER_ALL_TRAFFIC_TEMPLATE = """
[Interface]
PrivateKey = {private_key}
Address = 192.168.42.{ipv4_segment:d}/32

[Peer]
PublicKey = {public_key}
PresharedKey = {pre_shared_key}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = wireguard.example.com:51820
"""

PEER_LAN_TRAFFIC_TEMPLATE = """
[Interface]
PrivateKey = {private_key}
Address = 192.168.42.{ipv4_segment:d}/32

[Peer]
PublicKey = {public_key}
PresharedKey = {pre_shared_key}
AllowedIPs = 192.168.2.0/24
Endpoint = wireguard.example.com:51820
"""

PEER_WG_CONFIG_TEMPLATE = """
# Name: {name}
[Peer]
PublicKey = {public_key}
PresharedKey = {pre_shared_key}
AllowedIPs = 192.168.42.{ipv4_segment:d}/32
"""

CONFIG = {
    "PEER_DATA_DIR": "peer-data",
    "WG_CONFIG_FILE": "sample.conf"
}

def save_peer_data(peer_name, private_key, ipv4_segment, public_key, pre_shared_key):
    peer_data = {
        "private_key": private_key,
        "ipv4_segment": ipv4_segment,
        "public_key": public_key,
        "pre_shared_key": pre_shared_key
    }

    peer_data_file_path = os.path.join(CONFIG["PEER_DATA_DIR"], peer_name + "-data.json")

    with open(peer_data_file_path, "x") as peer_data_file:
        peer_data_file.write(json.dumps(peer_data))

    os.chmod(peer_data_file_path, 0o600)

def get_peer_data(peer_name):
    peer_data_file_path = os.path.join(CONFIG["PEER_DATA_DIR"], peer_name + "-data.json")

    with open(peer_data_file_path, "r") as peer_data_file:
        peer_data = json.loads(peer_data_file.read())

    return peer_data

def add_peer_to_wg_config(peer_name):
    peer_data = get_peer_data(peer_name)

    with open(CONFIG["WG_CONFIG_FILE"], "a") as wireguard_config:
        wireguard_config.write("\n")
        wireguard_config.write(PEER_WG_CONFIG_TEMPLATE.format(name = peer_name,
                                                              public_key = peer_data["public_key"],
                                                              pre_shared_key = peer_data["pre_shared_key"],
                                                              ipv4_segment = peer_data["ipv4_segment"]))