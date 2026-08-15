# MeshCore PacketTap

MeshCore PacketTap erfasst PacketTap-Daten eines MeshCore-Knotens, speichert die Rohdaten lokal, dekodiert sie und schreibt die ausgewerteten Informationen nach QuestDB. Zusätzlich steht eine lokale Weboberfläche zur Verfügung, um den Betriebszustand zu prüfen, Receiver und Importer sicher zu steuern und Repeater-Reports zu erzeugen.

## Datenfluss

```text
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
        +--> Repeater-Auswertung / Reports
        |
        v
 report_server.py
```

## Hauptkomponenten

### `receiver.py`

Der Receiver nimmt die PacketTap-TCP-Verbindung entgegen und verarbeitet PKTH- und PKTP-Frames.

Für den Dauerbetrieb sollte er mit `--append` gestartet werden:

```powershell
python receiver.py --append
```

Damit werden bestehende Capture-Dateien fortgesetzt und nicht überschrieben.

Der Receiver unterstützt einen sicheren Single-Instance-Schutz und einen kontrollierten externen Stop:

```text
state/receiver.lock
state/receiver.stop
```

### `packettap_importer.py`

Der Importer liest `packettap_capture.log`, dekodiert die enthaltenen MeshCore-Pakete und schreibt die Daten nach QuestDB.

Für den Dauerbetrieb:

```powershell
python packettap_importer.py --follow
```

Der Importer verwendet einen persistenten Checkpoint:

```text
state/importer.state
```

Dadurch kann er nach einem Neustart am zuletzt bestätigten Stand fortsetzen.

Zusätzlich:

```text
state/importer.lock
state/importer.stop
```

### `report_server.py`

Die lokale Weboberfläche dient als PacketTap-Kommandozentrale.

Start:

```powershell
python report_server.py
```

Standardmäßig ist sie erreichbar unter:

```text
http://127.0.0.1:8080
```

Die Weboberfläche bietet derzeit:

- QuestDB-Verbindungsstatus
- Status von Receiver und Importer
- Starten, geordnetes Stoppen und Neustarten der Dienste
- Anzeige des Importer-Checkpoints
- Loganzeige
- Repeater-Report-Erzeugung
- Bearbeitung der lokalen `report_config.json`

Die Dienststeuerung verwendet dieselben Lock- und Stop-Dateien wie Receiver und Importer. Es werden keine harten Prozessabbrüche verwendet.

## Konfiguration

Die lokale Konfiguration liegt in:

```text
report_config.json
```

Diese Datei ist standortspezifisch und sollte nicht ins Repository eingecheckt werden.

Als Vorlage dient:

```text
report_config.example.json
```

Nach dem Klonen kann die Beispieldatei kopiert werden:

```powershell
Copy-Item report_config.example.json report_config.json
```

Anschließend können die lokalen Werte angepasst oder später über die Weboberfläche geändert werden.

## Verzeichnisse

```text
reports/   erzeugte Repeater-Reports
logs/      Logs der von der Weboberfläche gestarteten Prozesse
state/     Lock-, Stop- und Checkpoint-Dateien
docs/      technische Dokumentation
```

## Sicheres Stoppen

Receiver und Importer sollten nicht hart beendet werden.

Manuell kann ein geordneter Stop über die jeweilige Stop-Datei ausgelöst werden:

```powershell
New-Item -ItemType File state\receiver.stop
New-Item -ItemType File state\importer.stop
```

Die laufenden Prozesse erkennen die Datei selbst und durchlaufen ihren regulären Shutdown.

Beim Importer ist das besonders wichtig, da vor dem Prozessende ausstehende QuestDB-Schreibvorgänge abgeschlossen und der Checkpoint aktualisiert werden.

## Doppelstarts

Receiver und Importer besitzen einen echten Betriebssystem-Dateilock:

- Windows: `msvcrt.locking()`
- Linux: `fcntl.flock()`

Eine zweite Instanz desselben Dienstes wird dadurch abgewiesen.

## Weitere Dokumentation

Die technischen Hintergründe und die getroffenen Designentscheidungen sind beschrieben in:

[`docs/architecture.md`](docs/architecture.md)

## Aktueller Entwicklungsstand

Der aktuelle Stand ist für Windows getestet. Die verwendeten Mechanismen für Locking, Stop-Dateien und Prozesssteuerung sind bewusst so ausgelegt, dass sie später auch unter Linux verwendet werden können.
