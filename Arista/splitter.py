import json
import os
import glob

from cursor import (
    load_cursor,
    save_cursor,
    reset_cursor
)

from cache import load_cache, already_scanned, save_cache, clear_cache

INPUT_FILE = "output/clean_ips.txt"
OUTPUT_FILE = "output/current_part.txt"


def load_config():
    try:
        config_path = os.path.join(os.path.dirname(__file__), "config.json")
        with open(config_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except:
        return {}


def write_lines(
    path,
    lines
):
    with open(
        path,
        "w",
        encoding="utf-8"
    ) as f:
        f.write(
            "\n".join(lines)
        )


def count_lines(path):

    total = 0

    try:
        with open(
            path,
            "r",
            encoding="utf-8"
        ) as f:
            for line in f:
                if line.strip():
                    total += 1
    except:
        return 0

    return total


def read_chunk(
    path,
    start,
    size
):

    chunk = []
    idx = 0

    try:

        with open(
            path,
            "r",
            encoding="utf-8"
        ) as f:

            for line in f:

                line = line.strip()

                if not line:
                    continue

                if idx < start:
                    idx += 1
                    continue

                chunk.append(line)

                if len(chunk) >= size:
                    break

                idx += 1

    except:
        return []

    return chunk


def clean_stage_files():
    files_to_clean = [
        "output/tcp_live.txt",
        "output/tls_live.txt",
        "output/https_live.txt",
        "output/fingerprint_results.txt",
        "output/https_meta.json",
        "output/current_part.txt"
    ]
    for f in files_to_clean:
        if os.path.exists(f):
            os.remove(f)
            print(f"REMOVED STAGE: {f}")


def clean_output_files():
    files_to_clean = [
        "output/results.txt",
        "output/domains_raw.txt",
        "output/domains.txt",
        "output/live_bank.txt",
        "output/geo_cache.json"
    ]
    print("=" * 60)
    print("[SPLITTER] clean_output_files() CALLED")
    print("[SPLITTER] Files to be cleaned (best_ips.txt is SAFE):")
    for f in files_to_clean:
        print(f"[SPLITTER]   - {f}")
    print("=" * 60)
    for f in files_to_clean:
        if os.path.exists(f):
            os.remove(f)
            print(f"REMOVED: {f}")
        else:
            print(f"[SPLITTER] FILE NOT FOUND: {f}")


def split_file(
    infile=INPUT_FILE
):

    cfg = load_config()

    batch_size = cfg.get(
        "batch_size",
        20000
    )

    ports = cfg.get("ports", [])

    total = count_lines(
        infile
    )

    print(f"[SPLITTER] TOTAL_IPS_IN_CLEAN_FILE: {total}")

    if total <= 0:

        write_lines(
            OUTPUT_FILE,
            []
        )

        print(
            "NO CLEAN IPS"
        )

        return OUTPUT_FILE

    cursor = load_cursor()

    print(f"[SPLITTER] CURRENT_CURSOR: {cursor}")
    print(f"[SPLITTER] PROGRESS: {round((cursor/total)*100, 2)}%")

    clean_stage_files()

    clear_cache()

    scanned_cache = {}

    if cursor >= total:
        print("=" * 60)
        print("ALL IPS COMPLETED - RESTARTING FROM BEGINNING")
        print("=" * 60)
        
        clean_output_files()
        clean_stage_files()
        
        reset_cursor()
        cursor = 0
        print(f"[SPLITTER] CURSOR RESET TO: {cursor}")

    available_ips = []
    line_idx = 0
    skip_count = 0

    try:
        with open(infile, "r", encoding="utf-8") as f:
            for line in f:
                ip = line.strip()
                if not ip:
                    continue

                if skip_count < cursor:
                    skip_count += 1
                    continue

                available_ips.append(ip)
                line_idx += 1

                if len(available_ips) >= batch_size:
                    break
    except:
        pass

    print(f"[SPLITTER] AVAILABLE_IPS_IN_BATCH: {len(available_ips)}")

    if not available_ips:
        if cursor >= total:
            print("RESTARTING SCAN CYCLE")
            reset_cursor()
            clean_stage_files()
            clean_output_files()
            return split_file(infile)
        print("NO NEW IPS AVAILABLE")
        write_lines(OUTPUT_FILE, [])
        return OUTPUT_FILE

    next_cursor = cursor + len(available_ips)
    if next_cursor > total:
        next_cursor = total

    save_cursor(next_cursor)

    write_lines(OUTPUT_FILE, available_ips)

    percent = round(
        (
            next_cursor / total
        ) * 100,
        2
    )

    if percent > 100:
        percent = 100

    print(
        f"TOTAL={total} "
        f"NEW={len(available_ips)} "
        f"PROGRESS={percent}%"
    )

    best_file = "output/best_ips.txt"
    if os.path.exists(best_file):
        best_size = os.path.getsize(best_file)
        best_lines = count_lines(best_file)
        print(f"[SPLITTER] best_ips.txt EXISTS: SIZE={best_size} bytes, LINES={best_lines}")
    else:
        print(f"[SPLITTER] best_ips.txt DOES NOT EXIST")

    return OUTPUT_FILE


if __name__ == "__main__":
    split_file()
