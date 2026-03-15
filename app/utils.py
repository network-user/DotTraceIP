import os


def init_files():
    if not os.path.exists("data"):
        os.makedirs("data")

    for file in ["data/target_ips.txt", "data/proxies.txt"]:
        if not os.path.exists(file):
            open(file, "w").close()


def read_lines(filepath):
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        return []


def init_result_file(filename):
    os.makedirs(os.path.dirname(filename) or ".", exist_ok=True)
    open(filename, "w", encoding="utf-8").close()


def append_result(data, filename):
    with open(filename, "a", encoding="utf-8") as f:
        f.write(f"=== IP: {data['IP']} ===\n")
        for k, v in data.items():
            if k != "IP":
                f.write(f"{k}: {v}\n")
        f.write("\n")