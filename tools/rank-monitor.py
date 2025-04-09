import re

LOG_FILE = "contiki_log.txt"

def detect_anomalies(log_file):
    ranks = {}
    with open(log_file, "r") as file:
        for line in file:
            match = re.search(r"Node (\d+) rank: (\d+)", line)
            if match:
                node_id, rank = int(match.group(1)), int(match.group(2))
                if node_id in ranks and abs(ranks[node_id] - rank) > 10:
                    print(f"Anomaly detected! Node {node_id}: {ranks[node_id]} → {rank}")
                ranks[node_id] = rank

if __name__ == "__main__":
    detect_anomalies(LOG_FILE)
