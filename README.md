# MeshCore PacketTap

MeshCore PacketTap erfasst MeshCore-Verkehr, dekodiert die empfangenen Pakete und schreibt die ausgewerteten Informationen nach QuestDB. Eine lokale Weboberfläche dient als Kommandozentrale für den laufenden Betrieb und für die Auswertung des beobachteten Mesh.

Für die Datenerfassung stehen aktuell zwei Wege zur Verfügung:

1. **PacketTap-Receiver** mit angepasster PacketTap-Firmware, `receiver.py` und `packettap_importer.py`.
2. **MeshCore TCP Companion** mit Standard-MeshCore-Companion-Firmware und direkter Erfassung über `mc_rx_analyzer.py`.

Beide Wege erzeugen eine für Mesh-, Repeater- und Nachbar-Auswertungen kompatible QuestDB-Datenbasis. Die Weboberfläche unterstützt mehrere umschaltbare Beobachtungsstandorte.

## Aktueller Stand

Der aktuelle Entwicklungsstand umfasst insbesondere:

- zuverlässige PacketTap-Erfassung und QuestDB-Import
- direkte Erfassung über einen Standard-MeshCore-TCP-Companion
- mehrere umschaltbare Standortprofile
- editierbare Profil-IDs und Löschen von Standortprofilen
- Anzeigename des Standorts als primäre Bezeichnung in Oberfläche und Reports
- Receivername und Public Key als dezente technische Zusatzinformation
- standortbezogene Mesh-Auswertung
- detaillierte Repeater-Auswertung
- Analyse direkter Nachbarn
- interaktive Kartenansichten
- konfigurierbaren Geo-Plausibilitätsfilter gegen fehlerhafte Advert-Koordinaten
- Erhalt der unveränderten Rohkoordinaten in QuestDB
- Report-Vorschau und gezieltes dauerhaftes Speichern als PDF

## Erfassungswege

### PacketTap-Receiver

```text
MeshCore / PacketTap-Firmware
        |
        v
   receiver.py
        |
        +--> packettap_capture.bin
        +--> packettap_capture.log
        +--> packettap_stream.bin
        |
        v
packettap_importer.py
        |
        v
     QuestDB
```

### MeshCore TCP Companion

```text
MeshCore Standard-Companion
        |
       TCP
        |
        v
mc_rx_analyzer.py
        |
        v
meshcore_decoder.py
        |
        v
     QuestDB
```

Der Companion-Weg verwendet `RX_LOG_DATA` und übernimmt unter anderem RSSI, SNR, Receiver-Identität und Companion-Informationen direkt aus der TCP-Verbindung.

Der eigene Beobachtungsstandort wird aus den per `APPSTART` gelieferten Informationen einschließlich `adv_lat` und `adv_lon` in `mc_contacts` eingetragen. Dadurch kann auch ein Companion-basierter Standort in Karten und Reports geografisch aufgelöst werden.

## Hauptkomponenten

### `receiver.py`

Nimmt die PacketTap-TCP-Verbindung entgegen und verarbeitet PKTH- und PKTP-Frames.

```powershell
python receiver.py --append
```

Single-Instance-Schutz und kontrollierter Stop:

```text
state/receiver.lock
state/receiver.stop
```

### `packettap_importer.py`

Liest `packettap_capture.log`, dekodiert MeshCore-Pakete und schreibt die Daten nach QuestDB.

```powershell
python packettap_importer.py --follow
```

Persistenter Checkpoint und Prozesssteuerung:

```text
state/importer.state
state/importer.lock
state/importer.stop
```

### `mc_rx_analyzer.py`

Der Companion-Collector verarbeitet `RX_LOG_DATA` direkt und schreibt unter anderem:

```text
mc_rx
mc_contacts
mc_contact_observations
mc_companion_info
```

Wesentliche Eigenschaften:

- RSSI und SNR aus `RX_LOG_DATA`
- Receiver-Identität in `mc_rx`
- passive ADVERT-Kontakte in `mc_contacts`
- ADVERT- und DISCOVER_RESP-Historie in `mc_contact_observations`
- Companion-Informationen einschließlich Firmware, Build und Noise Floor
- eigene Standortposition aus `APPSTART`
- automatischer Reconnect
- RX-Watchdog
- sauberer Shutdown über `Ctrl+C` und systemd `SIGTERM`

### `repeater_report.py`

Erzeugt die Auswertung eines ausgewählten Repeaters. Der Beobachtungsstandort wird mit dem Anzeigenamen des Standortprofils dargestellt; Receivername und Public Key erscheinen als technische Zusatzinformation.

`mc_contact_observations` kann je nach Erfassungsweg eine designierte Zeitspalte `ts` oder `timestamp` besitzen. Beide Varianten werden unterstützt.

### `mesh_report.py`

Erzeugt einen standortbezogenen Report über das tatsächlich beobachtete Mesh. Dazu gehören Last, Routing-Verteilung, Repeater-Aktivität, Nachbarn und geografische Ausdehnung.

Für Karten werden nur plausible Koordinaten verwendet. Die Rohkoordinaten in QuestDB bleiben unverändert.

### `report_server.py`

Start:

```powershell
python report_server.py
```

Standard:

```text
http://127.0.0.1:8080
```

Navigation:

```text
Übersicht | Mesh | Repeater | Nachbarn | Einstellungen
```

## Standortprofile

Über die Standortauswahl im Kopfbereich kann zwischen mehreren Beobachtungsstandorten gewechselt werden.

Ein Standortprofil enthält unter anderem:

- Profil-ID
- Anzeigename
- Collector-Typ
- QuestDB Host und Port
- Receivername
- Receiver Public Key / ID
- maximale Kartenentfernung

Die **Profil-ID ist editierbar**. Standortprofile können gelöscht werden; der letzte verbleibende Standort ist gegen Löschen geschützt.

Der Anzeigename wird in der Weboberfläche und in den Reports als primäre Standortbezeichnung verwendet.

## Mesh-Karte

Die Mesh-Seite enthält neben der Report-Erzeugung eine interaktive Karte des beobachteten Mesh der letzten 28 Tage.

Sie zeigt:

- beobachtete Repeater
- Repeater mit plausiblen Koordinaten
- wegen unplausibler Position ausgefilterte Einträge
- den konfigurierten maximalen Kartenradius

Eine Repeatersuche erlaubt das gezielte Hervorheben eines Repeaters.

## Geo-Plausibilitätsfilter

Fehlerhafte Koordinaten in Repeater-Adverts werden bewusst **nicht aus QuestDB gelöscht**. Stattdessen werden sie nur für Karten und geografische Auswertungen gefiltert.

```text
Advert-Koordinaten
        +
Position des Beobachtungsstandorts
        +
Entfernung <= max_geo_distance_km
        |
        v
plausible Kartenposition
```

Standard:

```text
max_geo_distance_km = 500
```

Der Wert wird pro Standortprofil gespeichert und kann unter **Einstellungen** geändert werden. `0` deaktiviert den Distanzfilter.

Damit bleiben die empfangenen Rohdaten vollständig nachvollziehbar, während falsche Positionsangaben die Mesh- und Nachbarkarten nicht über tausende Kilometer verzerren.

Auch bei der Nachbar-Auswertung wird eine Position außerhalb des eingestellten Radius nicht für Entfernung oder Verbindungslinie verwendet.

## Einstellungen

Die lokale Konfiguration liegt in:

```text
report_config.json
```

Sie ist installationsspezifisch und sollte nicht ins Repository eingecheckt werden.

Eine Mehrstandort-Konfiguration enthält konzeptionell beispielsweise:

```json
{
  "active_site": "hornisgrinde",
  "sites": {
    "hornisgrinde": {
      "name": "Hornisgrinde",
      "collector_type": "companion",
      "questdb_host": "127.0.0.1",
      "questdb_port": 9000,
      "receiver_name": "DK0A",
      "receiver_id": "<public-key>",
      "max_geo_distance_km": 500
    },
    "stutensee": {
      "name": "Stutensee - Spoeck",
      "collector_type": "packettap",
      "questdb_host": "127.0.0.1",
      "questdb_port": 9000,
      "receiver_name": "Stutensee - Spoeck",
      "receiver_id": "<public-key>",
      "max_geo_distance_km": 500
    }
  }
}
```

Weitere globale Einstellungen wie Ausgabeordner, Web Host/Port, Skripte, Startargumente, Logs, Locks und Checkpoints bleiben Teil der Konfiguration.

## Report-Vorschau und PDF

Mesh- und Repeater-Reports werden zunächst als Browser-Vorschau geöffnet. Die Navigation bleibt erhalten.

Über **Speichern** kann ein Report dauerhaft als PDF abgelegt werden. Die Nachbar-Auswertung kann ebenfalls als PDF gespeichert werden.

Für die PDF-Erzeugung wird lokal Microsoft Edge oder Google Chrome im Headless-Modus verwendet.

## Datenmodell-Kompatibilität

Für die aktuellen Reports werden von beiden Erfassungswegen kompatibel befüllt:

```text
mc_rx
mc_contacts
mc_contact_observations
mc_companion_info
```

PacketTap-spezifische Felder wie `capture_sequence`, `crc_ok`, `received_unix_ns`, `packettap_version` oder `packettap_flags` stehen beim TCP-Companion nicht zwingend zur Verfügung.

## Sicheres Stoppen

PacketTap Receiver und Importer sollten geordnet beendet werden:

```powershell
New-Item -ItemType File state\receiver.stop
New-Item -ItemType File state\importer.stop
```

`mc_rx_analyzer.py` verarbeitet `Ctrl+C` und systemd `SIGTERM` über einen geordneten Shutdown-Pfad.

## Betrieb im lokalen Netzwerk

Standardmäßig bindet sich die Weboberfläche an `127.0.0.1:8080`. Für den Zugriff im lokalen Netzwerk kann `web_host` beispielsweise auf `0.0.0.0` gesetzt werden.

Da die Weboberfläche Steuerfunktionen bereitstellt, sollte der Netzwerkzugriff nur in einer vertrauenswürdigen Umgebung freigegeben werden.

## Getestete Erfassungswege

### PacketTap

- angepasste MeshCore-Flow/PacketTap-Firmware
- PacketTap TCP Receiver
- Capture-Dateien plus `packettap_importer.py`
- Windows getestet

### TCP Companion

- Standard MeshCore Companion Firmware
- Heltec V3
- direkte TCP-Erfassung mit `mc_rx_analyzer.py`
- Linux/systemd getestet
- RSSI/SNR erfolgreich übernommen
- passive ADVERT- und DISCOVER_RESP-Beobachtungen gespeichert
- eigener Standort aus `APPSTART` geografisch aufgelöst

## Weitere Dokumentation

Technische Hintergründe und Designentscheidungen:

[`docs/architecture.md`](docs/architecture.md)
