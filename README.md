# MeshCore PacketTap

MeshCore PacketTap erfasst MeshCore-Verkehr, dekodiert empfangene Pakete und schreibt die ausgewerteten Informationen nach QuestDB. Eine Weboberfläche dient der Auswertung des beobachteten Mesh; unter Windows werden die zentralen Komponenten als Dienste betrieben.

Für die Datenerfassung stehen aktuell zwei Wege zur Verfügung:

1. **PacketTap-Receiver** mit angepasster PacketTap-Firmware, `receiver.py` und `packettap_importer.py`.
2. **MeshCore TCP Companion** mit Standard-MeshCore-Companion-Firmware und direkter Erfassung über `mc_rx_analyzer.py`.

Beide Wege erzeugen eine für Mesh-, Repeater- und Nachbar-Auswertungen kompatible QuestDB-Datenbasis.

## Aktueller Stand

Der aktuelle Stand umfasst insbesondere:

- zuverlässige PacketTap-Erfassung und QuestDB-Import
- direkte Erfassung über einen Standard-MeshCore-TCP-Companion
- getrennte DEV- und PROD-Umgebungen
- Windows-Dienstbetrieb für Receiver, Importer, Report-Webserver und Service-Admin
- getrennte QuestDB-Instanzen für DEV und PROD
- zentrale Dienstverwaltung für PROD und DEV über `admin_server.py`
- mehrere umschaltbare Standortprofile
- standortbezogene Mesh-Auswertung
- detaillierte Repeater-Auswertung
- Analyse direkter Nachbarn
- interaktive Kartenansichten
- konfigurierbaren Geo-Plausibilitätsfilter
- Report-Vorschau mit direktem PDF-Download über den Browser

## DEV-/PROD-Aufbau

Die Windows-Umgebungen sind funktional weitgehend angeglichen, verwenden aber getrennte Datenbanken und eigene lokale Konfigurationen.

```text
PROD 192.168.1.2
├─ QuestDB                     :9000
├─ PacketTap Receiver          :9001
├─ Report Web                  :8080
├─ Service Admin Controller    :8081
└─ Windows-Dienste für Receiver, Importer, Web und Admin

DEV 192.168.1.90
├─ QuestDB                     :9000
├─ PacketTap Receiver          :9001
├─ Report Web                  :8080
├─ Service Admin Agent         :8082
└─ Windows-Dienste für Receiver, Importer, Web und Admin
```

Für DEV ist ein eigener PacketTap-Repeater vorgesehen. Dadurch kann die komplette Pipeline unabhängig von PROD getestet werden.

### PacketTap-Pipeline

```text
PacketTap-Repeater
        |
        | TCP :9001
        v
receiver.py
        |
        v
packettap_capture.log
        |
        v
packettap_importer.py
        |
        v
QuestDB :9000
        |
        v
report_server.py :8080
```

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

Der Receiver lauscht in der aktuellen Windows-Installation auf TCP-Port `9001`.

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

Der eigene Beobachtungsstandort wird aus den per `APPSTART` gelieferten Informationen einschließlich `adv_lat` und `adv_lon` in `mc_contacts` eingetragen.

## Hauptkomponenten

### `receiver.py`

Nimmt die PacketTap-TCP-Verbindung entgegen und verarbeitet PKTH- und PKTP-Frames.

Manueller Start zu Diagnosezwecken:

```powershell
python receiver.py --append --host 0.0.0.0 --port 9001
```

Im regulären Windows-Betrieb läuft der Receiver als Dienst:

```text
MeshCorePacketTapReceiver
```

Single-Instance-Schutz und Stop-Datei bleiben intern vorhanden:

```text
state/receiver.lock
state/receiver.stop
```

Die bevorzugte Steuerung erfolgt jedoch über den Windows-Dienst bzw. `admin_server.py`.

### `packettap_importer.py`

Liest `packettap_capture.log`, dekodiert MeshCore-Pakete und schreibt die Daten nach QuestDB.

Manueller Start zu Diagnosezwecken:

```powershell
python packettap_importer.py --follow --questdb-host <HOST> --questdb-port 9000
```

Im regulären Windows-Betrieb läuft der Importer als Dienst:

```text
MeshCorePacketTapImporter
```

Persistenter Checkpoint und Prozessschutz:

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

### `mesh_report.py`

Erzeugt einen standortbezogenen Report über das tatsächlich beobachtete Mesh. Dazu gehören Last, Routing-Verteilung, Repeater-Aktivität, Nachbarn und geografische Ausdehnung.

### `report_server.py`

Der Report-Webserver bietet die zentrale Auswertungsoberfläche.

Manueller Start:

```powershell
python report_server.py
```

Im regulären Windows-Betrieb läuft er als Dienst:

```text
MeshCorePacketTapWeb
```

Typischer Aufruf im lokalen Netz:

```text
http://<HOST>:8080/
```

Navigation:

```text
Übersicht | Mesh | Repeater | Nachbarn | Einstellungen
```

## Service Admin

### `admin_server.py`

`admin_server.py` dient zur Statusanzeige und Steuerung der Windows-Dienste. Derselbe Code wird in zwei Betriebsarten verwendet:

- **Controller** auf PROD
- **Agent** auf DEV

### PROD Controller

Auf PROD läuft der Controller typischerweise unter:

```text
http://192.168.1.2:8081/
```

Er zeigt PROD und DEV gemeinsam an und unterstützt `Start`, `Stop` und `Neustart` für:

```text
QuestDB
MeshCorePacketTapReceiver
MeshCorePacketTapImporter
MeshCorePacketTapWeb
```

Der Admin-Dienst selbst wird bewusst nicht über die eigene Weboberfläche gesteuert.

### DEV Agent

Auf DEV läuft derselbe `admin_server.py` im Agent-Modus auf Port `8082`. Der Agent stellt eine authentifizierte API für den PROD-Controller bereit.

Auf beiden Windows-Rechnern läuft der Admin-Server als:

```text
MeshCorePacketTapAdmin
```

## Windows-Dienste und WinSW

Die produktiv verwendeten lokalen WinSW-Dateien sind installationsspezifisch und werden nicht eingecheckt.

Im Repository liegen stattdessen Beispiele:

```text
service/
├─ MeshCorePacketTapAdmin.example.xml
├─ MeshCorePacketTapReceiver.example.xml
├─ MeshCorePacketTapImporter.example.xml
└─ MeshCorePacketTapWeb.example.xml
```

Die lokalen Dateien heißen beispielsweise:

```text
service/MeshCorePacketTapAdmin.xml
service/MeshCorePacketTapReceiver.xml
service/MeshCorePacketTapImporter.xml
service/MeshCorePacketTapWeb.xml
```

Die lokalen XML-Dateien und WinSW-EXE-Dateien werden durch `.gitignore` ausgeschlossen. Vor Verwendung der Example-Dateien müssen insbesondere Python-Pfad, Hostnamen und installationsspezifische Parameter angepasst werden.

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

Die Profil-ID ist editierbar. Standortprofile können gelöscht werden; der letzte verbleibende Standort ist gegen Löschen geschützt.

## Mesh-Karte

Die Mesh-Seite enthält neben der Report-Erzeugung eine interaktive Karte des beobachteten Mesh der letzten 28 Tage.

Sie zeigt:

- beobachtete Repeater
- Repeater mit plausiblen Koordinaten
- wegen unplausibler Position ausgefilterte Einträge
- den konfigurierten maximalen Kartenradius

Eine Repeatersuche erlaubt das gezielte Hervorheben eines Repeaters.

## Geo-Plausibilitätsfilter

Fehlerhafte Koordinaten in Repeater-Adverts werden bewusst nicht aus QuestDB gelöscht. Stattdessen werden sie nur für Karten und geografische Auswertungen gefiltert.

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

## Konfiguration

### Report-Konfiguration

Die lokale Report-Konfiguration liegt in:

```text
report_config.json
```

Sie ist installationsspezifisch und wird nicht ins Repository eingecheckt.

### Admin-Konfiguration

Die lokale Admin-Konfiguration liegt in:

```text
admin_config.json
```

Sie enthält unter anderem:

- Betriebsart `controller` oder `agent`
- Web-Port
- Admin-Zugangsdaten des Controllers
- Agent-Token
- Hostdefinitionen
- verwaltete Windows-Dienste

Die echte `admin_config.json` wird nicht eingecheckt. Als Vorlage dient:

```text
admin_config.example.json
```

Passwörter und Agent-Tokens dürfen nicht in das Repository übernommen werden.

## Report-Vorschau und PDF

Mesh-, Repeater- und Nachbar-Reports können als PDF heruntergeladen werden.

```text
Report erzeugen
      |
      v
Browser-Vorschau
      |
      v
PDF herunterladen
      |
      v
Browser-Download auf dem Client
```

Das PDF wird serverseitig temporär mit Microsoft Edge oder Google Chrome im Headless-Modus erzeugt und anschließend direkt an den Browser ausgeliefert. Die erzeugten PDFs werden nicht dauerhaft als Report-Dateien auf dem Server abgelegt.

Für parallele oder aufeinanderfolgende PDF-Jobs verwendet `report_server.py` getrennte temporäre Browserprofile.

## Datenmodell-Kompatibilität

Für die aktuellen Reports werden von beiden Erfassungswegen kompatibel befüllt:

```text
mc_rx
mc_contacts
mc_contact_observations
mc_companion_info
```

PacketTap-spezifische Felder wie `capture_sequence`, `crc_ok`, `received_unix_ns`, `packettap_version` oder `packettap_flags` stehen beim TCP-Companion nicht zwingend zur Verfügung.

## Betrieb und Steuerung

Im Windows-Betrieb sollten die Dienste bevorzugt über den Service Admin oder die Windows-Dienstverwaltung gesteuert werden.

Typische Dienste:

```text
QuestDB
MeshCorePacketTapReceiver
MeshCorePacketTapImporter
MeshCorePacketTapWeb
MeshCorePacketTapAdmin
```

Für Diagnosezwecke können einzelne Python-Skripte weiterhin manuell in PowerShell gestartet werden. Vorher sollte der zugehörige Windows-Dienst gestoppt werden, damit keine zweite Instanz entsteht.

## Betrieb im lokalen Netzwerk

Aktuelle typische Ports:

```text
8080  Report Web
8081  Service Admin Controller auf PROD
8082  Service Admin Agent auf DEV
9000  QuestDB
9001  PacketTap TCP Receiver
```

Der Service Admin besitzt Steuerfunktionen und sollte ausschließlich in einem vertrauenswürdigen lokalen Netzwerk betrieben werden. Der Controller verwendet HTTP-Basic-Authentifizierung; die Agent-Kommunikation verwendet einen Bearer-Token. Beide Zugangsdaten werden ausschließlich in lokalen, nicht versionierten Konfigurationsdateien gespeichert.

## Getestete Erfassungswege

### PacketTap

- angepasste MeshCore-Flow/PacketTap-Firmware
- PacketTap TCP Receiver
- Capture-Dateien plus `packettap_importer.py`
- Windows-Dienstbetrieb getestet
- getrennte DEV-/PROD-QuestDB
- zentrale Dienststeuerung über `admin_server.py`

### TCP Companion

- Standard MeshCore Companion Firmware
- Heltec V3
- direkte TCP-Erfassung mit `mc_rx_analyzer.py`
- Linux/systemd getestet
- RSSI/SNR erfolgreich übernommen
- passive ADVERT- und DISCOVER_RESP-Beobachtungen gespeichert
- eigener Standort aus `APPSTART` geografisch aufgelöst

## Repository und lokale Dateien

Nicht ins Repository gehören insbesondere:

```text
report_config.json
admin_config.json
state/
logs/
reports/
packettap_capture.bin
packettap_capture.log
packettap_stream.bin
public_channel_keys.json
service/*.xml
service/*.exe
```

Versioniert werden dagegen die reproduzierbaren Beispiele:

```text
admin_config.example.json
service/*.example.xml
```

## Weitere Dokumentation

Technische Hintergründe und Designentscheidungen:

[`docs/architecture.md`](docs/architecture.md)
