import os

CONFIG = {
    "CLIENT_CONFIG_DIR": "client-configs",
    "CLIENT_CONFIG_TEMPLATE_DIR": "client-config-templates"
}

def generate_client_configs(client_name, priv_key, ipv4_segment, public_key, psk):
	# steps:
    # 1. get and modify templates with argument values
    # 2. save configs and set permissions to 0o600 (umask 0o177)
    
    config_all_traffic_path = os.path.join(CONFIG["CLIENT_CONFIG_DIR"], client_name + "-all-traffic.conf")
    
    with open(os.path.join(CONFIG["CLIENT_CONFIG_TEMPLATE_DIR"], "client-all-traffic.conf"), "r") as template, open(config_all_traffic_path, "x") as clientcfg:
        modified_template = template.read().replace("[PEER_PRIVATE_KEY]", priv_key)
        modified_template = modified_template.replace("[PEER_IPV4_ADDR_LAST_DIGIT]", ipv4_segment)
        modified_template = modified_template.replace("[ENDPOINT_PUBLIC_KEY]", public_key)
        modified_template = modified_template.replace("[PRESHARED_KEY]", psk)
        
        clientcfg.write(modified_template)
    
    os.chmod(config_all_traffic_path, 0o600)
    
    
    config_specific_traffic_path = os.path.join(CONFIG["CLIENT_CONFIG_DIR"], client_name + "-specific-traffic.conf")
    
    with open(os.path.join(CONFIG["CLIENT_CONFIG_TEMPLATE_DIR"], "client-specific-traffic.conf"), "r") as template, open(config_specific_traffic_path, "x") as clientcfg:
        modified_template = template.read().replace("[PEER_PRIVATE_KEY]", priv_key)
        modified_template = modified_template.replace("[PEER_IPV4_ADDR_LAST_DIGIT]", ipv4_segment)
        modified_template = modified_template.replace("[ENDPOINT_PUBLIC_KEY]", public_key)
        modified_template = modified_template.replace("[PRESHARED_KEY]", psk)
        
        clientcfg.write(modified_template)
    
    os.chmod(config_all_traffic_path, 0o600)