# MeshCore PacketTap – QuestDB Datenmodell

Stand: 2026-08-14  
Quelle: produktive QuestDB des Projekts `meshcore-packettap`

## Überblick

Aktuell sind in der QuestDB fünf Tabellen vorhanden:

- `mc_rx`
- `mc_advert`
- `mc_companion_info`
- `mc_contacts`
- `mc_contact_observations`

Für `mc_rx`, `mc_advert`, `mc_contacts` und `mc_contact_observations` liegen Schema-Informationen vor.
Für `mc_companion_info` liegt derzeit nur der Tabellenname vor; Spalten und Semantik sind noch nicht dokumentiert.

---

# 1. mc_rx

Zentrale Tabelle für empfangene MeshCore-Pakete und deren ausgewertete Routing-/Pfadinformationen.

Designated timestamp:

- `ts`

## Spalten

| Spalte | Typ | Bedeutung / aktuelle Interpretation |
|---|---|---|
| `ts` | TIMESTAMP | Empfangs-/Beobachtungszeitpunkt; designated timestamp |
| `repeater` | SYMBOL | Letzter Repeater / letztes Pfadelement vor dem PacketTap-Empfänger |
| `prev_hop` | SYMBOL | Vorletztes Pfadelement |
| `sender_node` | SYMBOL | Erstes Pfadelement / Ursprung innerhalb des beobachteten Pfads |
| `payload_type` | SYMBOL | Dekodierter Payload-Typ, z. B. `GRP_TXT`, `ADVERT`, `REQ` |
| `region` | SYMBOL | Region / Routing-Region, falls vorhanden |
| `channel` | SYMBOL | Kanalbezug, falls vorhanden |
| `packet_id` | SYMBOL | Paketkennung |
| `region_code` | SYMBOL | Region-Code |
| `grp_txt_sender_name` | SYMBOL | Sendername bei Group-Text-Nachrichten |
| `packet_payload_sha256` | SYMBOL | Hash des dekodierten Packet-Payloads |
| `txt_msg_dest_hash` | SYMBOL | Destination-Hash bei Text-Nachrichten |
| `txt_msg_src_hash` | SYMBOL | Source-Hash bei Text-Nachrichten |
| `payload_route_type` | SYMBOL | Routingtyp; beobachtete Werte 0,1,2,3 |
| `hop_count` | BYTE | Anzahl Hops des beobachteten Pfads |
| `grp_txt_body` | VARCHAR | Textinhalt bei Group-Text-Nachrichten |
| `frame_bytes` | LONG | Frame-Größe in Bytes |
| `frame_bits` | LONG | Frame-Größe in Bits |
| `path_hash_size` | LONG | Größe eines Path-Hash-Elements in Bytes |
| `airtime_ms` | DOUBLE | Berechnete Airtime |
| `nodes` | VARCHAR | Vollständiger beobachteter Pfad, getrennt mit `>` |
| `payload_hex` | VARCHAR | Payload in Hex |
| `packet_payload_hex` | VARCHAR | Dekodierter Packet-Payload in Hex |
| `capture_sequence` | LONG | Capture-Sequenznummer |
| `rssi_dbm` | SHORT | RSSI am PacketTap-Empfänger |
| `snr_db` | DOUBLE | SNR am PacketTap-Empfänger |
| `crc_ok` | BOOLEAN | CRC-Status |
| `frame_length` | LONG | Frame-Länge |
| `received_unix_ns` | LONG | Empfangszeit als Unix-Nanosekunden |
| `received_utc` | VARCHAR | Empfangszeit als UTC-Text |
| `peer` | VARCHAR | Peer-/Verbindungsinformation |
| `timestamp_ms` | LONG | Zeitstempel in Millisekunden |
| `packettap_version` | BYTE | PacketTap-Protokollversion |
| `packettap_flags` | BYTE | PacketTap-Flags |
| `receiver_id` | SYMBOL | Eindeutige ID des PacketTap-Empfängers |
| `receiver_name` | SYMBOL | Anzeigename des PacketTap-Empfängers |
| `receiver_type` | SYMBOL | Typ des Empfängers |
| `receiver_ip` | SYMBOL | IP des Empfängers |
| `receiver_port` | LONG | Port des Empfängers |
| `receiver_version` | SYMBOL | Versionsinformation des Empfängers |
| `receiver_time_ns` | LONG | Zeitinformation des Empfängers |

## Beobachtete Routingtypen

Aus den vorliegenden Daten:

| `payload_route_type` | Pakete |
|---:|---:|
| 0 | 49.325 |
| 1 | 15.332 |
| 2 | 3.737 |
| 3 | 2 |

Aktuell verwendete Interpretation:

- `0` = Transport Flood
- `1` = Flood
- `2` = Direct
- `3` = Transport Direct

## Beobachtete Payload-Typen

| Payload-Typ | Pakete |
|---|---:|
| `GRP_TXT` | 28.030 |
| `REQ` | 10.220 |
| `TEXT_MSG` | 7.744 |
| `RESPONSE` | 7.231 |
| `ADVERT` | 6.745 |
| `PATH` | 4.399 |
| `ANON_REQ` | 2.265 |
| `CONTROL` | 854 |
| `ACK` | 528 |
| `TRACE` | 299 |
| `MULTIPART` | 82 |
| `GRP_DATA` | 2 |
| `UNKNOWN_12` | 1 |

## Pfad-Semantik

Beispiel:

`fd6d>1dea>842c>4099>8ae5`

mit:

- `sender_node = fd6d`
- `prev_hop = 4099`
- `repeater = 8ae5`
- `hop_count = 4`
- `path_hash_size = 2`

Aktuelle Interpretation:

- `nodes` enthält den vollständigen beobachteten Mesh-Pfad.
- Das letzte Element von `nodes` entspricht `repeater`.
- Das vorletzte Element entspricht `prev_hop`.
- Das erste Element entspricht `sender_node`.
- Bei `path_hash_size = 2` besteht jedes Pfadelement aus 2 Byte = 4 Hex-Zeichen.
- Pfadelemente sind Präfixe der vollständigen Public Keys aus `mc_contacts`.

---

# 2. mc_contacts

Kontakt-/Node-Stammdaten bzw. zeitbezogene Snapshots bekannter MeshCore-Kontakte.

Designated timestamp:

- `ts`

## Spalten

| Spalte | Typ | Bedeutung / aktuelle Interpretation |
|---|---|---|
| `ts` | TIMESTAMP | Zeitpunkt des Kontakt-Snapshots |
| `public_key` | SYMBOL | Vollständiger 32-Byte Public Key |
| `adv_name` | SYMBOL | Advert-/Node-Name |
| `contact_type` | SYMBOL | Kontakt-Typ; in den gezeigten Repeater-Datensätzen `null` |
| `out_path` | SYMBOL | gespeicherter Ausgangspfad |
| `flags` | LONG | Kontakt-/Advert-Flags |
| `out_path_hash_mode` | LONG | Hash-Modus des Ausgangspfads |
| `out_path_len` | LONG | Länge des Ausgangspfads |
| `last_advert` | LONG | Zeitpunkt/Marker des letzten Adverts |
| `adv_lat` | DOUBLE | Advert-Latitude |
| `adv_lon` | DOUBLE | Advert-Longitude |
| `lastmod` | LONG | letzter Änderungszeitpunkt/-marker |
| `node_role` | SYMBOL | Rolle, z. B. `repeater` |
| `source_type` | SYMBOL | Quelle, z. B. `advert` |

## Besonderheit

Ein Public Key kann mehrfach mit unterschiedlichen `ts`-Werten vorkommen.
Beispiel: `Bruchsal Tower` erscheint mehrfach mit demselben Public Key.

Für Auswertungen sollte daher:

- nach `public_key` dedupliziert werden
- für aktuelle Metadaten bevorzugt der neueste Datensatz nach `ts` verwendet werden

## Beispiel: Bruchsal Tower

Name:

`Bruchsal Tower`

Public Key:

`11b1a13a8f978262b717b55e033b3a9ff73dcbb6e4c337ef10dcd7d24bf45cf7`

Koordinaten in den vorliegenden Datensätzen:

- `adv_lat = 49.11073`
- `adv_lon = 8.61148`

Rolle:

- `node_role = repeater`

Quelle:

- `source_type = advert`

---

# 3. mc_contact_observations

Zeitbezogene Beobachtungen bekannter Kontakte an konkreten PacketTap-Empfängern.

Die Tabelle enthält zeitbezogene Beobachtungen von Kontakten an konkreten PacketTap-Empfängern und verbindet vollständige Public Keys mit Receiver-, Hop-, RSSI- und SNR-Informationen.

Designated timestamp:

- `ts`

## Spalten

| Spalte | Typ | Bedeutung / aktuelle Interpretation |
|---|---|---|
| `ts` | TIMESTAMP | Zeitpunkt der Beobachtung |
| `public_key` | SYMBOL | Vollständiger Public Key des beobachteten Kontakts |
| `receiver_id` | SYMBOL | ID des PacketTap-Empfängers |
| `receiver_name` | SYMBOL | Name des PacketTap-Empfängers |
| `node_role` | SYMBOL | Rolle, z. B. `repeater`, `companion` |
| `hop_count` | BYTE | Hop Count bei dieser Beobachtung |
| `rssi_dbm` | SHORT | RSSI bei dieser Beobachtung |
| `snr_db` | DOUBLE | SNR bei dieser Beobachtung |
| `region` | SYMBOL | Region, z. B. `#europe`, `#de-bw` |
| `packet_payload_sha256` | SYMBOL | Hash des zugehörigen Payloads |
| `public_key_bytes` | BYTE | Anzahl direkt verfügbarer Public-Key-Bytes |
| `discover_tag` | SYMBOL | Discovery-Tag, falls vorhanden |
| `discover_snr` | DOUBLE | Discovery-SNR, falls vorhanden |
| `source_type` | SYMBOL | Herkunft der Observation |

## Beispielreceiver aus den vorliegenden Daten

Name:

`Stutensee - Spoeck`

Receiver-ID:

`8627a8b8866ebe35561f4793d6f6a4ca9c660c34d6008ce6047097f7d9c169d3`

---

# 4. mc_advert

Spezialisierte Tabelle für erkannte Advert-Ereignisse.

Designated timestamp:

- `ts`

## Spalten

| Spalte | Typ | Bedeutung / aktuelle Interpretation |
|---|---|---|
| `ts` | TIMESTAMP | Zeitpunkt des Advert-Ereignisses |
| `repeater` | SYMBOL | letzter Repeater / letztes Pfadelement |
| `sender_node` | SYMBOL | Sender-/erstes Pfadelement |
| `prev_hop` | SYMBOL | vorheriger Hop |
| `channel` | SYMBOL | Kanal |
| `region` | SYMBOL | Region |
| `packet_id` | SYMBOL | Paket-ID |
| `advert_text` | VARCHAR | dekodierter Advert-Text |

## Aktueller Status

Die Tabelle enthält spezialisierte, dekodierte Advert-Ereignisse.

---

# 5. mc_companion_info

Tabelle für zeitbezogene Status- und Identitätsinformationen des lokalen Companion-/PacketTap-Geräts.

Designated timestamp:

- `ts`

Aktuell enthält die Tabelle 16 Datensätze.

## Spalten

| Spalte | Typ | Bedeutung / aktuelle Interpretation |
|---|---|---|
| `ts` | TIMESTAMP | Zeitpunkt des Status-/Info-Snapshots; designated timestamp |
| `model` | SYMBOL | Geräte-/Plattformmodell, z. B. `heltec_v4` oder `PacketTap` |
| `firmware` | SYMBOL | Firmware-/Softwareversion, z. B. `v1.16.0 FLOW 1.4` oder `1` |
| `build` | SYMBOL | Build-Datum bzw. Build-Kennung, z. B. `Aug 8 2026` |
| `node_name` | SYMBOL | Name des lokalen Nodes bzw. PacketTap-Empfängers |
| `public_key` | SYMBOL | Public Key bzw. lokale Gerätekennung |
| `noise_floor` | LONG | Noise-Floor-Wert; in den vorliegenden Datensätzen `null` |
| `tcp_connected` | LONG | TCP-Verbindungsstatus; beobachtet wurde `1` für verbunden |
| `node_role` | SYMBOL | Rolle des lokalen Nodes, z. B. `repeater`; ältere Datensätze können `null` enthalten |

## Beobachtete Geräte

### Stutensee - Spoeck

- `model = heltec_v4`
- `firmware = v1.16.0 FLOW 1.4`
- `build = Aug 8 2026`
- `node_name = Stutensee - Spoeck`
- `public_key = 8627a8b8866ebe35561f4793d6f6a4ca9c660c34d6008ce6047097f7d9c169d3`
- `tcp_connected = 1`
- `node_role = repeater`

### PacketTap Receiver

- `model = PacketTap`
- `firmware = 1`
- `node_name = PacketTap Receiver`
- `public_key = ptap01`
- `tcp_connected = 1`
- `node_role = repeater` in neueren Datensätzen
- ältere Datensätze enthalten für `node_role` noch `null`

## Charakter der Tabelle

Die Tabelle enthält mehrere zeitlich aufeinanderfolgende Snapshots desselben lokalen Geräts. Sie ist daher keine reine Stammdatentabelle, sondern bildet Änderungen bzw. wiederholte Statusmeldungen über die Zeit ab.

Der Wert in `public_key` ist nicht zwingend immer ein kryptografischer 32-Byte MeshCore-Public-Key. Beim Eintrag `PacketTap Receiver` wird beispielsweise die lokale Kennung `ptap01` verwendet.

---
