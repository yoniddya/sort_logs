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


def extract_hours(data):
    return list(map(lambda row: int(row[0].split()[1].split(":")[0]), data))

def convert_bytes_to_kb(data):
    return list(map(lambda row: int(row[5]) / 1024, data))

def filter_sensitive_ports_v2(data):
    return list(filter(lambda row: row[3] in {"22", "23", "3389"}, data))

def filter_night_activity(data):
    return list(filter(lambda row: 0 <= int(row[0].split()[1].split(":")[0]) < 6, data))

def build_suspicion_checks():
    return {
        "EXTERNAL_IP":   lambda row: not (row[1].startswith("192.168") or row[1].startswith("10.")),
        "SENSITIVE_PORT": lambda row: row[3] in {"22", "23", "3389"},
        "LARGE_PACKET":   lambda row: int(row[5]) > 5000,
        "NIGHT_ACTIVITY": lambda row: 0 <= int(row[0].split()[1].split(":")[0]) < 6
    }

def detect_row_suspicions(row, checks):
    return list(filter(lambda key: checks[key](row), checks))

def process_log(data, checks):
    return list(filter(
        lambda item: len(item[1]) > 0,
        map(lambda row: (row, detect_row_suspicions(row, checks)), data)
    ))
