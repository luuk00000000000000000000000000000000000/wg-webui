import os
import json
import re
import base64
import io
import zipfile
import subprocess

from flask import Flask, render_template, abort, redirect, url_for, request, make_response, flash

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

CONFIG = {
    "PEER_DATA_DIR": "peer-data",
    "WG_CONFIG_FILE": "sample.conf",
    "WG_INTERFACE_NAME": "wg0"
}

app = Flask(__name__)
app.secret_key = os.urandom(24)

def save_peer_data(peer_name, private_key, ipv4_segment, public_key, pre_shared_key):
    peer_data = {
        "private_key": private_key,
        "ipv4_segment": ipv4_segment,
        "public_key": public_key,
        "pre_shared_key": pre_shared_key
    }

    peer_data_file_path = os.path.join(CONFIG["PEER_DATA_DIR"], peer_name + "-data.json")

    try:
        with open(peer_data_file_path, "x") as peer_data_file:
            peer_data_file.write(json.dumps(peer_data))
    except Exception as e:
        raise Exception(f"failed to save peer data with error [{e}]")
    else:
        os.chmod(peer_data_file_path, 0o600)

def get_peer_data(peer_name):
    peer_data_file_path = os.path.join(CONFIG["PEER_DATA_DIR"], peer_name + "-data.json")

    try:
        with open(peer_data_file_path, "r") as peer_data_file:
            peer_data = json.loads(peer_data_file.read())
    except Exception as e:
        raise Exception(f"failed to get peer data with error [{e}]")
    else:
        return peer_data

def add_peer_to_wg_config(public_key, pre_shared_key, ipv4_segment):  
    wg_command = [
        "sudo",
        "wg",
        "set",
        CONFIG["WG_INTERFACE_NAME"],
        "peer",
        public_key,
        "preshared-key",
        "/dev/stdin",
        "allowed-ips",
        f"192.168.42.{ipv4_segment}/32"
    ]

    ip_command = [
        "sudo",
        "ip",
        "-4",
        "route",
        "add",
        f"192.168.42.{ipv4_segment}/32",
        "dev",
        CONFIG["WG_INTERFACE_NAME"]
    ]
    
    try:
        subprocess.run(wg_command, input = pre_shared_key, text = True, check = True)
        subprocess.run(ip_command, check = True)
    except Exception as e:
        raise Exception(f"command failed to run! error {e}")
        
def remove_peer_from_wg_config(public_key, ipv4_segment):   
    wg_command = [
        "sudo",
        "wg",
        "set",
        CONFIG["WG_INTERFACE_NAME"],
        "peer",
        public_key,
        "remove"
    ]

    ip_command = [
        "sudo",
        "ip",
        "-4",
        "route",
        "delete",
        f"192.168.42.{ipv4_segment}/32",
        "dev",
        CONFIG["WG_INTERFACE_NAME"]
    ]
   
    try:
        subprocess.run(wg_command, check = True)
        subprocess.run(ip_command, check = True)
    except Exception as e:
        raise Exception(f"command failed to run! error {e}")
        
def get_next_available_ip():
    wg_command = [
        "sudo",
        "wg",
        "show",
        CONFIG["WG_INTERFACE_NAME"],
        "allowed-ips"
    ]

    try:
        wg_show_output = subprocess.run(wg_command, capture_output = True, check = True)
    except Exception as e:
        raise Exception(f"command failed to run! error {e}")
    
    ip_segments = re.findall(r"^(?:[A-Za-z0-9+/]{42}[AEIMQUYcgkosw480]=)\t(?:[0-9]{1,3}\.){3}([0-9]{1,3})", wg_show_output.stdout, flags = re.MULTILINE)

    if ip_segments:
        next_ip = int(max(ip_segments)) + 1
    else:
        next_ip = 2

    if next_ip > 254:
        raise Exception("no more ip's available in wireguard subnet. wow!")
    else:
        return next_ip

def generate_peer_keys():
    priv_key_command = [
        "sudo",
        "wg",
        "genkey"
    ]
    
    pub_key_command = [
        "sudo",
        "wg",
        "pubkey",
        "/dev/stdin"
    ]

    psk_command = [
        "sudo",
        "wg",
        "genpsk"
    ]

    try:
        priv_key_command_output = subprocess.run(priv_key_command, capture_output = True, check = True)
        generated_private_key = re.search(r"^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw480]=", priv_key_command_output.stdout).group()

        pub_key_command_output = subprocess.run(pub_key_command, input = generated_private_key, text = True, capture_output = True, check = True)
        generated_public_key = re.search(r"^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw480]=", pub_key_command_output.stdout).group()

        psk_command_output = subprocess.run(psk_command, capture_output = True, check = True)
        generated_pre_shared_key = re.search(r"^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw480]=", psk_command_output.stdout).group()
    except Exception as e:
        raise Exception(f"failed to generate peer keys with error {e}")
    else:
        return (generated_private_key, generated_public_key, generated_pre_shared_key)

def get_endpoint_pubkey():
    endpoint_pubkey_command = [
        "sudo",
        "wg",
        "show",
        CONFIG["WG_INTERFACE_NAME"],
        "public-key"
    ]

    try:
        endpoint_pubkey_command_output = subprocess.run(endpoint_pubkey_command, capture_output = True, check = True)
        endpoint_public_key = re.search(r"^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw480]=", endpoint_pubkey_command_output.stdout).group()
    except Exception as e:
        raise Exception(f"failed to get endpoint public key with error {e}")
    else:
        return endpoint_public_key

def get_list_of_peers():
    try:
        data_files = os.listdir(CONFIG["PEER_DATA_DIR"])
    except Exception as e:
        raise Exception(f"failed to get list of peers with error {e}")

    peers = []

    for file in data_files:
        regex_search = re.search(r"^([a-z0-9-]*)(-data\.json)$", file)

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

def generate_peer_config_bundle(peer_name):
    peer_config_lan, peer_config_all = get_peer_configs(peer_name)

    zip_buffer = io.BytesIO()

    with zipfile.ZipFile(zip_buffer, "x", zipfile.ZIP_DEFLATED) as zip_file:
        for file_name, data in [(f"{peer_name}-lan.conf", peer_config_lan),
                                (f"{peer_name}-all.conf", peer_config_all)]:
            zip_file.writestr(file_name, data)

    return zip_buffer.getvalue()

def sanitize_peer_name(peer_name):
    if not peer_name:
        return None
    
    return re.sub(r"[^a-z0-9-]", "", peer_name)

@app.route("/", methods = ["GET"])
def index():
    peer_qr_list = []

    try:
        for peer in get_list_of_peers():
            peer_lan_qr, peer_all_qr = generate_peer_qr_codes(peer)
            peer_qr_list.append({ "name": peer, "lan_qr": peer_lan_qr, "all_qr": peer_all_qr })
    except Exception as e:
        flash(f"{e}", "error")

    return render_template("index.html", peers = peer_qr_list)

@app.route("/add", methods = ["POST"])
def add_peer():
    peer_name = sanitize_peer_name(request.form.get("peer_name"))
    if not peer_name:
        flash("peer name can't be empty!", "warning")
        return redirect(url_for("index"))

    try:
        peer_list = get_list_of_peers()

        if peer_name not in peer_list:
            ipv4_segment = get_next_available_ip()
            private_key, public_key, pre_shared_key = generate_peer_keys()

            save_peer_data(peer_name, private_key, ipv4_segment, public_key, pre_shared_key)
            add_peer_to_wg_config(public_key, pre_shared_key, ipv4_segment)

            flash(f"{peer_name} was added successfully!", "info")
        else:
            flash(f"peer name {peer_name} is already in peer list", "warning")

        return redirect(url_for("index"))
    except Exception as e:
        flash(f"{e}", "error")
        return redirect(url_for("index"))


@app.route("/delete", methods = ["POST"])
def delete_peer():
    peer_name = sanitize_peer_name(request.form.get("peer_name"))
    if not peer_name:
        abort(400)

    try:
        peer_list = get_list_of_peers()

        if peer_name in peer_list:
            peer_data = get_peer_data(peer_name)

            remove_peer_from_wg_config(peer_data["public_key"], peer_data["ipv4_segment"])

            os.remove(os.path.join(CONFIG["PEER_DATA_DIR"], f"{peer_name}-data.json"))

            flash(f"{peer_name} was deleted successfully!", "info")
        else:
            flash(f"peer name {peer_name} not found in peer list", "warning")
        
        return redirect(url_for("index"))
    except Exception as e:
        flash(f"{e}", "error")
        return redirect(url_for("index"))

@app.route("/peer-config/<peer_name>/<config_type>", methods = ["GET"])
def get_config(config_type, peer_name):
    peer_name = sanitize_peer_name(peer_name)
    if not peer_name:
        abort(400)

    if config_type not in ("lan", "all", "zip"):
        abort(404)

    try:
        peer_list = get_list_of_peers()

        if peer_name in peer_list:
            if config_type == "zip":
                response = make_response(generate_peer_config_bundle(peer_name))
                response.headers["Content-Disposition"] = f"attachment; filename=\"{peer_name}-bundle.zip\""
                response.headers["Content-Type"] = "application/zip"

                return response 
            else:
                response = make_response(get_peer_configs(peer_name)[{"lan": 0, "all": 1}.get(config_type)])
                response.headers["Content-Disposition"] = f"attachment; filename=\"{peer_name}-{config_type}.conf\""
                response.headers["Content-Type"] = "application/octet-stream"

                return response
        else:
            abort(404)
    except Exception as e:
        abort(500)