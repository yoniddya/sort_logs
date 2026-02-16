from pathlib import Path
import csv
PATH_TO_LOGS = Path("network_traffic.log")


def load_csv(path):
    with open(path, "r") as f:
        return [line.strip().split(",") for line in f]



def get_external_ips(data):
    return [row[0] for row in data
            if not (row[0].startswith("192.168") or row[0].startswith("10."))]



def filter_sensitive_ports(data):
    sensitive = {"22", "23", "3389"}
    return [row for row in data if row[1] in sensitive]



def filter_large_packets(data):
    return [row for row in data if int(row[2]) > 5000]



def tag_traffic(data):
    return [row + ["LARGE" if int(row[2]) > 5000 else "NORMAL"] for row in data]


def count_requests_by_ip(data):
    return {ip: sum(1 for row in data if row[0] == ip)
            for ip in {row[0] for row in data}}


def map_port_to_protocol(data):
    return {int(row[1]): row[3] for row in data}


def detect_suspicions(data):
    return {
        ip: [
            "EXTERNAL_IP"   if not (ip.startswith("192.168") or ip.startswith("10.")) else None,
            "PORT_SENSITIVE" if port in {"22", "23", "3389"} else None,
            "PACKET_LARGE"   if int(size) > 5000 else None,
            "NIGHT_ACTIVITY" if 0 <= int(time.split(":")[0]) < 6 else None
        ]
        for ip, port, size, _, time in data
    }


def filter_multi_suspicions(sus_dict):
    return {ip: susp for ip, susp in sus_dict.items() if len(susp) >= 2}
