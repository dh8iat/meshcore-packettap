# MeshCore PacketTap

MeshCore PacketTap erfasst PacketTap-Daten eines MeshCore-Knotens,
speichert die Rohdaten lokal, dekodiert sie und schreibt die
ausgewerteten Informationen nach QuestDB. Eine lokale Weboberfläche
dient als Kommandozentrale für den laufenden Betrieb und für die
Auswertung des beobachteten Mesh.

Die Weboberfläche umfasst aktuell die Bereiche **Übersicht**, **Mesh**,
**Repeater**, **Nachbarn** und **Einstellungen**. Reports werden
zunächst als Vorschau erzeugt und nur dauerhaft gespeichert, wenn dies
ausdrücklich ausgewählt wird.

## Datenfluss

``` text
MeshCore / PacketTap
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
        |
        +--> Repeater-Auswertung
        +--> Mesh-Auswertung
        +--> Nachbar-Auswertung
        |
        v
 report_server.py
        |
        +--> Browser-Vorschau
        +--> PDF-Report
```

## Voraussetzungen

Für die Python-Komponenten werden keine zusätzlichen Pakete aus einer
`requirements.txt` benötigt. Die Report-Skripte basieren auf der
Python-Standardbibliothek; `mesh_report.py` verwendet zusätzlich das
lokale Modul `repeater_report.py`.

Benötigt werden:

-   Python 3
-   eine erreichbare QuestDB mit den von PacketTap erzeugten Tabellen
-   `report_server.py`, `repeater_report.py` und `mesh_report.py` im
    selben Verzeichnis
-   eine lokale `report_config.json`
-   für das Speichern als PDF: Microsoft Edge oder Google Chrome

Die Kartenansichten verwenden Leaflet und eine Online-Kartenquelle. Für
die Darstellung der Hintergrundkarte muss beim Aufruf des Reports bzw.
der Weboberfläche eine Internetverbindung vorhanden sein.

## Hauptkomponenten

### `receiver.py`

Der Receiver nimmt die PacketTap-TCP-Verbindung entgegen und verarbeitet
PKTH- und PKTP-Frames.

Für den Dauerbetrieb sollte er mit `--append` gestartet werden:

``` powershell
python receiver.py --append
```

Damit werden bestehende Capture-Dateien fortgesetzt und nicht
überschrieben.

Der Receiver unterstützt einen Single-Instance-Schutz und einen
kontrollierten externen Stop:

``` text
state/receiver.lock
state/receiver.stop
```

### `packettap_importer.py`

Der Importer liest `packettap_capture.log`, dekodiert die enthaltenen
MeshCore-Pakete und schreibt die Daten nach QuestDB.

Für den Dauerbetrieb:

``` powershell
python packettap_importer.py --follow
```

Der Importer verwendet einen persistenten Checkpoint:

``` text
state/importer.state
```

Dadurch kann er nach einem Neustart am zuletzt bestätigten Stand
fortsetzen.

Zusätzlich werden verwendet:

``` text
state/importer.lock
state/importer.stop
```

### `repeater_report.py`

Erzeugt die Auswertung eines ausgewählten Repeaters für einen
definierten Beobachtungszeitraum.

Der Report wertet unter anderem aus:

-   Kennzahlen des Beobachtungsstandorts
-   Kennzahlen des untersuchten Repeaters
-   Routing-Verhalten
-   Advert-Verhalten
-   Repeater-Nachbarn
-   Unscoped-Nachbarn über größere Hop-Distanzen
-   Path-IDs und deren Zuordnung zu bekannten Repeatern
-   mehrdeutige Path-IDs ohne fälschliche eindeutige
    Public-Key-Zuordnung
-   Methodik der Auswertung

Die Zuordnung von Path-IDs berücksichtigt, dass verkürzte Hashes
mehrdeutig sein können. Mehrdeutige Kandidaten werden entsprechend als
solche dargestellt.

### `mesh_report.py`

Erzeugt einen standortbezogenen Report über das Mesh, das der
konfigurierte PacketTap-Receiver im gewählten Zeitraum tatsächlich
beobachtet hat.

Die Auswertung umfasst unter anderem:

-   Gesamtlast und Paketrate
-   Routing-Verteilung
-   Aktivität der beobachteten Repeater
-   direkte Nachbarn
-   Unscoped-Repeater in größerer Hop-Distanz
-   geografische Ausdehnung des beobachteten Mesh
-   Kartenansicht der Repeater mit bekannten Koordinaten

Die Repeater-Koordinaten werden aus `mc_contacts` verwendet, sofern dort
gültige Positionsdaten vorliegen.

### `report_server.py`

Die lokale Weboberfläche ist die PacketTap-Kommandozentrale.

Start:

``` powershell
python report_server.py
```

Standardmäßig ist sie anschließend erreichbar unter:

``` text
http://127.0.0.1:8080
```

Die Navigation besteht aus:

``` text
Übersicht | Mesh | Repeater | Nachbarn | Einstellungen
```

## Weboberfläche

### Übersicht

Die Übersicht zeigt den Betriebszustand der PacketTap-Verarbeitung. Dazu
gehören insbesondere:

-   QuestDB-Verbindungsstatus
-   Status von Receiver und Importer
-   Starten, geordnetes Stoppen und Neustarten der Dienste
-   Importer-Checkpoint
-   Logausgaben

Receiver und Importer werden dabei über ihre Lock- und Stop-Dateien
gesteuert. Die Weboberfläche verwendet keinen harten Prozessabbruch.

### Mesh

Die Mesh-Seite erzeugt einen standortbezogenen Mesh-Report für einen
frei wählbaren Zeitraum.

Als Vorauswahl wird ein Zeitraum von sieben Tagen verwendet.

Unterhalb der Report-Erzeugung wird zusätzlich eine interaktive **Karte
des beobachteten Mesh der letzten 28 Tage** angezeigt. Sie enthält die
beobachteten Repeater, soweit deren Koordinaten bekannt sind.

Die Karte bietet außerdem eine Repeatersuche, über die ein Repeater
gesucht und auf der Karte hervorgehoben werden kann.

### Repeater

Auf der Repeater-Seite kann ein einzelner Repeater ausgewählt und für
einen bestimmten Zeitraum untersucht werden.

Die Auswahl kann über den Repeaternamen bzw. einen eindeutigen
2-Byte-Hash erfolgen. Bekannte Repeater werden aus QuestDB geladen.

Auch hier ist der Zeitraum standardmäßig auf sieben Tage vorbelegt und
kann vor der Report-Erzeugung geändert werden.

### Nachbarn

Die Nachbar-Seite untersucht **direkte Nachbarn des konfigurierten
Beobachtungsstandorts**.

Für einen ausgewählten direkten Nachbarn werden unter anderem
dargestellt:

-   grundlegende Kennzahlen
-   Rang unter den direkten Nachbarn
-   Entfernung zum Beobachtungsstandort
-   Position und Kartenansicht mit Verbindung zwischen Receiver und
    Nachbar
-   zeitlicher Verlauf von RSSI
-   zeitlicher Verlauf von SNR
-   letzte direkte Adverts
-   letzter beobachteter Flood-Advert

Die Position des Nachbarn wird aus den in `mc_contacts` gespeicherten
Kontaktdaten verwendet.

Die RSSI- und SNR-Verläufe werden bewusst getrennt dargestellt, damit
beide Messgrößen unabhängig voneinander beurteilt werden können.

### Einstellungen

Die Einstellungen werden in folgender Datei gespeichert:

``` text
report_config.json
```

Über die Weboberfläche können unter anderem konfiguriert werden:

-   QuestDB Host und Port
-   Name und ID des Beobachtungsstandorts
-   Ausgabeordner
-   Web Host und Web Port
-   Receiver- und Importer-Skripte
-   Startargumente
-   Lock- und Stop-Dateien
-   Logverzeichnis
-   Importer-Checkpoint
-   automatischer Start von Receiver und Importer
-   Aktualisierungsintervall der Übersicht

Änderungen an Web Host oder Web Port werden erst nach einem Neustart des
Report-Servers aktiv.

## Report-Vorschau und PDF

Repeater- und Mesh-Reports werden nach der Erzeugung unmittelbar als
Vorschau im Browser geöffnet. Dabei bleibt die PacketTap-Navigation
erhalten, sodass direkt wieder zu Übersicht, Mesh, Repeater, Nachbarn
oder Einstellungen gewechselt werden kann.

Die Vorschau ist zunächst temporär. Ein Report wird nicht automatisch
dauerhaft im Ausgabeordner abgelegt.

Über **Speichern** kann der Report als PDF dauerhaft gespeichert werden.

Für die PDF-Erzeugung sucht PacketTap lokal nach einer geeigneten
Installation von Microsoft Edge oder Google Chrome und verwendet den
Browser im Headless-Modus.

Die Nachbar-Auswertung kann ebenfalls als PDF gespeichert werden.

## Konfiguration

Die lokale Konfiguration liegt in:

``` text
report_config.json
```

Diese Datei ist standortspezifisch und sollte nicht ins Repository
eingecheckt werden.

Als Vorlage kann eine Datei

``` text
report_config.example.json
```

verwendet werden.

Unter Windows kann sie beispielsweise kopiert werden mit:

``` powershell
Copy-Item report_config.example.json report_config.json
```

Anschließend werden die lokalen Werte angepasst oder über
**Einstellungen** in der Weboberfläche bearbeitet.

Eine typische Konfiguration enthält unter anderem:

``` json
{
  "questdb_host": "192.168.1.200",
  "questdb_port": 9000,
  "receiver_name": "ABC Repeater",
  "receiver_id": "",
  "output_dir": "reports",
  "web_host": "127.0.0.1",
  "web_port": 8080,
  "receiver_script": "receiver.py",
  "receiver_args": ["--append"],
  "importer_script": "packettap_importer.py",
  "importer_args": ["--follow"],
  "log_dir": "logs",
  "importer_state": "state/importer.state",
  "receiver_lock": "state/receiver.lock",
  "receiver_stop": "state/receiver.stop",
  "importer_lock": "state/importer.lock",
  "importer_stop": "state/importer.stop",
  "dashboard_refresh_seconds": 15,
  "auto_start_receiver": true,
  "auto_start_importer": true
}
```

Die konkreten Werte für QuestDB und Beobachtungsstandort müssen an die
jeweilige Installation angepasst werden.

## Verzeichnisse

``` text
reports/                 dauerhaft gespeicherte PDF-Reports
logs/                    Logs der von der Weboberfläche gestarteten Prozesse
state/                   Lock-, Stop- und Checkpoint-Dateien
state/report_preview/    temporäre Report-Vorschauen
docs/                    technische Dokumentation
map/                     lokale Karten-/Leaflet-Ressourcen, soweit vorhanden
```

Temporäre Report-Vorschauen sind nicht als dauerhaftes Report-Archiv
gedacht.

## Sicheres Stoppen

Receiver und Importer sollten nicht hart beendet werden.

Manuell kann ein geordneter Stop über die jeweilige Stop-Datei ausgelöst
werden:

``` powershell
New-Item -ItemType File state\receiver.stop
New-Item -ItemType File state\importer.stop
```

Die laufenden Prozesse erkennen die Datei selbst und durchlaufen ihren
regulären Shutdown.

Beim Importer ist dies besonders wichtig, da vor dem Prozessende
ausstehende QuestDB-Schreibvorgänge abgeschlossen und der Checkpoint
aktualisiert werden.

## Doppelstarts

Receiver und Importer besitzen einen Betriebssystem-Dateilock:

-   Windows: `msvcrt.locking()`
-   Linux: `fcntl.flock()`

Eine zweite Instanz desselben Dienstes wird dadurch abgewiesen.

## Betrieb im lokalen Netzwerk

Standardmäßig bindet sich die Weboberfläche an:

``` text
127.0.0.1:8080
```

Damit ist sie nur vom lokalen Rechner erreichbar.

Soll die Oberfläche beispielsweise unter Linux im lokalen Netzwerk
erreichbar sein, kann `web_host` entsprechend angepasst werden, zum
Beispiel:

``` json
"web_host": "0.0.0.0"
```

Dabei ist zu beachten, dass die Weboberfläche Steuerfunktionen für
Receiver und Importer bereitstellt. Der Netzwerkzugriff sollte deshalb
nur in einer vertrauenswürdigen Umgebung freigegeben werden.

## Weitere Dokumentation

Die technischen Hintergründe und Designentscheidungen sind beschrieben
in:

[`docs/architecture.md`](docs/architecture.md)

## Aktueller Entwicklungsstand

Der aktuelle Stand ist für Windows getestet. Die Mechanismen für
Locking, Stop-Dateien und Prozesssteuerung sind so ausgelegt, dass sie
auch unter Linux verwendet werden können.

Der Schwerpunkt der aktuellen Version liegt auf:

-   zuverlässiger PacketTap-Erfassung und QuestDB-Import
-   sicherer Steuerung von Receiver und Importer
-   standortbezogener Mesh-Auswertung
-   detaillierter Repeater-Auswertung
-   Analyse direkter Nachbarn
-   interaktiven Kartenansichten
-   einheitlicher Report-Darstellung
-   gezieltem dauerhaften Speichern als PDF
