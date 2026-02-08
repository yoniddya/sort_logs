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

def extracting_suspect_port(matrix):
    external_port = []
    suspect_port = ["22" , "23" , "3389"]
    for row in matrix:
        port = row[3]
        if port in suspect_port:
            external_port.append(row)
        else:
            continue
    return external_port


def sort_size_packet(matrix):
    big_packet = []
    for row in matrix:
        size_packet = row[-1]
        if int(size_packet) > 5000 :
            big_packet.append(row)
        else:
            continue
    return big_packet


def tag_traffic(matrix):
    tagged = []
    for row in matrix:
        size = int(row[-1])
        tag = "LARGE" if size > 5000 else "NORMAL"
        tagged.append(row + [tag])
    return tagged


def main():
    pass