import os
import json
import re
import base64
import io

from flask import Flask, render_template, abort, redirect, url_for, request

import qrcode
from qrcode.image.pure import PyPNGImage

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

app = Flask(__name__)

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

def add_peer_to_wg_config(name, public_key, pre_shared_key, ipv4_segment):
    with open(CONFIG["WG_CONFIG_FILE"], "a") as wireguard_config:
        wireguard_config.write("\n")
        wireguard_config.write(PEER_WG_CONFIG_TEMPLATE.format(name = name,
                                                              public_key = public_key,
                                                              pre_shared_key = pre_shared_key,
                                                              ipv4_segment = ipv4_segment))
        
def get_next_available_ip():
    with open(CONFIG["WG_CONFIG_FILE"], "r") as wireguard_config:
        ip_segments = re.findall(r"^AllowedIPs = (?:[0-9]{1,3}\.){3}([0-9]{1,3})", wireguard_config.read(), flags=re.MULTILINE)

    if ip_segments:
        next_ip = int(max(ip_segments)) + 1
    else:
        next_ip = 2

    if next_ip > 254:
        raise Exception("No IP addresses available")
    else:
        return next_ip

def generate_peer_keys():
    # TODO: add actual generation

    # wg genkey > privatekey
    generated_private_key = "priv_key_placeholder"
    # wg pubkey < privatekey > publickey
    generated_public_key = "pub_key_placeholder"
    # wg genpsk
    generated_pre_shared_key = "psk_placeholder"

    return (generated_private_key, generated_public_key, generated_pre_shared_key)

def get_endpoint_pubkey():
    # TODO: add actual key retrieval

    with open(CONFIG["WG_CONFIG_FILE"], "r") as wireguard_config:
        endpoint_private_key = re.findall(r"^PrivateKey = ([A-Za-z0-9+/]{42}[AEIMQUYcgkosw480]=)", wireguard_config.read(), flags=re.MULTILINE)

    # do wg pubkey < server_private_key
    endpoint_public_key = "endpoint_pub_key_placeholder"
    return endpoint_public_key

def get_list_of_peers():
    data_files = os.listdir(CONFIG["PEER_DATA_DIR"])

    peers = []

    for file in data_files:
        regex_search = re.search(r"^([a-z0-9]*)(-data\.json)$", file)

        if regex_search != None:
            peers.append(regex_search.group(1))

    return peers

def get_peer_configs(peer_name):
    peer_data = get_peer_data(peer_name)

    peer_config_lan = PEER_LAN_TRAFFIC_TEMPLATE.format(private_key = peer_data["private_key"],
                                                       ipv4_segment = peer_data["ipv4_segment"],
                                                       public_key = get_endpoint_pubkey(),
                                                       pre_shared_key = peer_data["pre_shared_key"])
    
    peer_config_all = PEER_ALL_TRAFFIC_TEMPLATE.format(private_key = peer_data["private_key"],
                                                       ipv4_segment = peer_data["ipv4_segment"],
                                                       public_key = get_endpoint_pubkey(),
                                                       pre_shared_key = peer_data["pre_shared_key"])
    
    return (peer_config_lan, peer_config_all)

def generate_peer_qr_codes(peer_name):
    qr_codes = []

    for config in get_peer_configs(peer_name):
        qr_buffer = io.BytesIO()

        qr_code = qrcode.make(config,
                              error_correction = qrcode.constants.ERROR_CORRECT_L,
                              box_size = 4,
                              image_factory = PyPNGImage)
        
        qr_code.save(qr_buffer)

        qr_codes.append(base64.b64encode(qr_buffer.getvalue()).decode("utf-8"))

    return qr_codes

@app.route("/", methods = ["GET"])
def index():
    peer_qr_list = []

    for peer in get_list_of_peers():
        peer_lan_qr, peer_all_qr = generate_peer_qr_codes(peer)
        peer_qr_list.append({ "name": peer, "lan_qr": peer_lan_qr, "all_qr": peer_all_qr })

    return render_template("index.html", peers = peer_qr_list)

@app.route("/add", methods = ["POST"])
def add_peer():
    peer_name = re.sub(r"[^a-z0-9-]", "", request.args.get("name"))

    peer_list = get_list_of_peers()

    if peer_name not in peer_list:
        ipv4_segment = get_next_available_ip()
        private_key, public_key, pre_shared_key = generate_peer_keys()

        save_peer_data(peer_name, private_key, ipv4_segment, public_key, pre_shared_key)
        add_peer_to_wg_config(peer_name, public_key, pre_shared_key, ipv4_segment)

        return redirect(url_for("index"))
    else:
        abort(400)
