from pathlib import Path
import csv
PATH_TO_LOGS = Path("network_traffic.log")


def load_csv(path):
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        reader = csv.reader(f)
        for row in reader:
            rows.append(row)
    return rows


def extracting_external_IP_addresses(matrix):
    external_IP = []
    for row in matrix:
        ip = row[1]
        if ip.startswith("10.") or ip.startswith("192.168."):
            continue
        else:
            external_IP.append(ip)
    return external_IP

