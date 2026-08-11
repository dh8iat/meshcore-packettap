#!/usr/bin/env python3
"""Find ADVERT packets by node name and show routing/region metadata."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from meshcore_decoder import decode_mc_rx_record


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("name", help="Teil des Node-Namens, Groß/Kleinschreibung egal")
    parser.add_argument(
        "log_file",
        nargs="?",
        type=Path,
        default=Path("packettap_capture.log"),
    )
    args = parser.parse_args()

    needle = args.name.casefold()
    found = 0

    with args.log_file.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            try:
                capture = json.loads(line)
            except json.JSONDecodeError:
                continue

            decoded = decode_mc_rx_record(
                capture.get("payload_hex"),
                capture,
            )
            if not decoded or decoded.get("payload_type") != "ADVERT":
                continue

            advert_name = str(decoded.get("advert_name") or "")
            if needle not in advert_name.casefold():
                continue

            found += 1
            print(f"\n[ADVERT {found}] line={line_number}")
            print(f"  name          : {advert_name}")
            print(f"  public_key    : {decoded.get('advert_public_key')}")
            print(f"  role          : {decoded.get('advert_node_role')}")
            print(f"  hops          : {decoded.get('advert_hop_count')}")
            print(f"  region_name   : {decoded.get('region_name')}")
            print(f"  region_code   : {decoded.get('region_code')}")
            print(f"  transport1    : {decoded.get('transport1')}")
            print(f"  transport2    : {decoded.get('transport2')}")
            print(f"  route_type    : {decoded.get('payload_route_type')}")
            print(f"  rssi_dbm      : {decoded.get('rssi_dbm')}")
            print(f"  snr_db        : {decoded.get('snr_db')}")
            print(f"  payload_hex   : {capture.get('payload_hex')}")

    print(f"\nFertig: {found} passende ADVERT(s) gefunden.")


if __name__ == "__main__":
    main()
