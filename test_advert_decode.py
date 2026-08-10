#!/usr/bin/env python3
"""Print decoded ADVERT packets from a PacketTap capture log."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from meshcore_decoder import decode_mc_rx_record


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "log_file",
        nargs="?",
        type=Path,
        default=Path("packettap_capture.log"),
    )
    args = parser.parse_args()

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

            found += 1
            print(
                f"[ADVERT {found}] line={line_number} "
                f"hops={decoded.get('advert_hop_count')} "
                f"rssi={decoded.get('rssi_dbm')}dBm "
                f"snr={decoded.get('snr_db')}dB"
            )
            print(f"  public_key : {decoded.get('advert_public_key')}")
            print(f"  name       : {decoded.get('advert_name')}")
            print(f"  role       : {decoded.get('advert_node_role')}")
            print(f"  timestamp  : {decoded.get('advert_timestamp')}")
            print(f"  flags      : {decoded.get('advert_flags')}")
            print(f"  latitude   : {decoded.get('advert_lat')}")
            print(f"  longitude  : {decoded.get('advert_lon')}")
            print(f"  error      : {decoded.get('advert_error')}")
            print()

    print(f"Fertig: {found} ADVERT(s) gefunden.")


if __name__ == "__main__":
    main()
