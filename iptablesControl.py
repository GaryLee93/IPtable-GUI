import subprocess
import json

def generate_iptables_command(rule):
    # INPUT
    cmd = ["sudo", "iptables", "-A", "INPUT"]
    cmd += ["-p", rule["protocol"]]
    if rule.get("ip"):
        cmd += ["-s", rule["ip"]]
    if rule.get("port"):
        cmd += ["--sport", rule["port"]]
    cmd_accept = cmd + ["-j"] + rule["action"].split()
    print(cmd_accept)
    subprocess.run(cmd_accept)
    if rule["quota"] == True:
        cmd_reject = cmd + ["-j", "REJECT"]
        subprocess.run(cmd_reject)
    # OUTPUT
    cmd = ["sudo", "iptables", "-A", "OUTPUT"]
    if rule.get("ip"):
        cmd += ["-d", rule["ip"]]
    cmd += ["-p", rule["protocol"]]
    if rule.get("port"):
        cmd += ["--dport", rule["port"]]
    cmd_accept = cmd + ["-j"] + rule["action"].split()
    subprocess.run(cmd_accept)
    if rule["quota"] == True:
        cmd_reject = cmd + ["-j", "REJECT"]
        subprocess.run(cmd_reject)
    return

udp_ports = {
    "53",   # DNS
    "67", "68",  # DHCP
    "69",   # TFTP
    "123",  # NTP
    "161", "162",  # SNMP
    "514",  # Syslog
    "5060",  # SIP
    "5353",  # mDNS
}

# {"ip": "<ip>", "mask": "<mask>", "port": "<port>", "limit": "<limit>"}
# <limit> = -1 for ACCEPT without limit, 0 for REJECT
def load_rules_from_json(file_path):
    # Clear the iptables rules
    subprocess.run(["sudo", "iptables", "-F"])
    with open(file_path, "r") as f:
        rules_data = json.load(f)        
    for item in rules_data:
        quota = False
        if item["limit"] == 0:
            action = "REJECT"
        else:
            action = "ACCEPT"
            if item["limit"] != -1:
                action += f" -m quota --quota {item['limit']}"
                quota = True
        ip = item.get('ip')
        if ip:
            if item.get('IPmask'):
                ip = f"{ip}/{item['IPmask']}"
        port = item.get("port")
        # protocol
        if port is not None:
            if port in udp_ports:
                protocol = "udp"
            else:
                protocol = "tcp"
        else:
            protocol = None
        rule = {
            "ip": ip,
            "protocol": protocol,
            "port": port,
            "action": action,
            "quota": quota
        }
        generate_iptables_command(rule)
    return

def check_iptables_status():
    result = subprocess.run(["sudo","iptables", "-L"], capture_output=True, text=True)
    if result.returncode == 0:
        print("Iptables is running.")
        print(result.stdout)
    else:
        print("Iptables is not running.")
    return