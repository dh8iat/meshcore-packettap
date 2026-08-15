# PacketTap Architektur und Betriebslogik

Dieses Dokument beschreibt den aktuellen technischen Aufbau von MeshCore PacketTap und insbesondere die Mechanismen, die für einen sicheren Dauerbetrieb eingeführt wurden.

## 1. Ziel

PacketTap soll empfangene MeshCore-Pakete dauerhaft erfassen, dekodieren, in QuestDB speichern und anschließend für Reports auswertbar machen.

Dabei sind drei Punkte besonders wichtig:

1. Capture-Daten dürfen beim Neustart des Receivers nicht versehentlich überschrieben werden.
2. Der Importer darf nach einem Neustart keine noch nicht bestätigten Daten überspringen.
3. Receiver und Importer dürfen nicht versehentlich mehrfach parallel gestartet werden.

## 2. Receiver

`receiver.py` nimmt die TCP-Verbindung des PacketTap-Knotens entgegen.

Unterstützt werden:

- PKTH v1/v2 für die Receiver-Identität
- PKTP v1 für Radio-Frames

Nach einem gültigen HELLO werden unter anderem Receiver-ID, Name, Gerätetyp, Firmware, Build und Node-Rolle den Capture-Datensätzen zugeordnet.

### 2.1 Capture-Dateien

Der Receiver schreibt:

```text
packettap_capture.bin
packettap_capture.log
packettap_stream.bin
```

`packettap_capture.log` ist die JSON-Lines-Grundlage für den Importer.

Für den Dauerbetrieb wird der Receiver mit `--append` gestartet:

```powershell
python receiver.py --append
```

Ohne `--append` werden die Ausgabedateien neu angelegt.

### 2.2 Geordneter Stop

Zusätzlich zu den vorhandenen Tastatur-/Signalwegen beobachtet der Receiver:

```text
state/receiver.stop
```

Wird diese Datei erzeugt, setzt der Receiver seinen internen Stop-Zustand und durchläuft denselben regulären Shutdown-Pfad.

Dabei werden unter anderem:

- der TCP-Server beendet,
- laufende Tasks beendet,
- Capture-Dateien geschlossen,
- die Stop-Datei entfernt,
- der Instance-Lock freigegeben.

### 2.3 Single-Instance-Schutz

Der Receiver verwendet:

```text
state/receiver.lock
```

Die Datei ist nicht nur eine PID-Markierung. Der laufende Prozess hält einen echten Betriebssystem-Dateilock:

```text
Windows -> msvcrt.locking()
Linux   -> fcntl.flock()
```

Ein zweiter Receiver kann denselben Lock nicht übernehmen und beendet seinen Start sofort.

Damit wird verhindert, dass mehrere Receiver gleichzeitig versuchen, Port 9000 oder dieselben Capture-Dateien zu verwenden.

## 3. Importer

`packettap_importer.py` liest `packettap_capture.log`, dekodiert die MeshCore-Pakete und schreibt die gewonnenen Informationen nach QuestDB.

Dauerbetrieb:

```powershell
python packettap_importer.py --follow
```

### 3.1 Checkpoint

Im Follow-Modus verwendet der Importer standardmäßig:

```text
state/importer.state
```

Der Checkpoint enthält insbesondere:

- Capture-Datei
- bestätigten Byte-Offset
- Aktualisierungszeit

Beim Start wird dieser Offset geladen und die Verarbeitung dort fortgesetzt.

### 3.2 Datenintegrität beim Checkpoint

Der Checkpoint darf Daten nicht überspringen, die QuestDB noch nicht bestätigt hat.

Daher gilt im Importer:

```text
Daten verarbeiten
    |
    v
QuestDB schreiben
    |
    v
writer.flush(), wenn notwendig
    |
    v
Checkpoint speichern
```

Beim regulären Beenden wird derselbe Sicherheitsgedanke beibehalten:

```text
ausstehende Daten flushen
    |
    v
Checkpoint aktualisieren
    |
    v
QuestDB Writer stoppen
    |
    v
Stop-Datei entfernen
    |
    v
Instance-Lock freigeben
```

Ein harter Prozessabbruch würde diesen Ablauf umgehen und wird deshalb von der Weboberfläche bewusst nicht verwendet.

### 3.3 Geordneter Stop

Der Importer beobachtet im Follow-Modus:

```text
state/importer.stop
```

Wird die Datei erkannt, endet die Follow-Schleife regulär. Anschließend läuft der bestehende Cleanup-/Checkpoint-Pfad weiter.

### 3.4 Single-Instance-Schutz

Der Importer verwendet:

```text
state/importer.lock
```

Wie beim Receiver wird ein echter OS-Dateilock gehalten.

Das ist besonders wichtig, weil zwei parallel laufende Importer dieselbe Capture-Datei und denselben Checkpoint verwenden und gleichzeitig nach QuestDB schreiben könnten.

## 4. Weboberfläche

`report_server.py` ist die lokale PacketTap-Kommandozentrale.

Die Oberfläche steuert Receiver und Importer nicht über Prozessnamen oder harte Betriebssystem-Signale.

Stattdessen nutzt sie exakt die Mechanismen der Dienste:

```text
Status     -> OS-Lock prüfen
Start      -> Python-Prozess starten
Stop       -> Stop-Datei erzeugen
Restart    -> Stop-Datei erzeugen
              auf Lock-Freigabe warten
              Prozess neu starten
```

### 4.1 Kein Force-Kill

Die Weboberfläche verwendet bewusst keinen harten Kill für Receiver oder Importer.

Falls ein Prozess nach einer Stop-Anforderung nicht innerhalb der vorgesehenen Wartezeit endet, bleibt er aktiv und die Oberfläche meldet diesen Zustand.

Die Datenintegrität hat Vorrang vor einem erzwungenen Neustart.

### 4.2 Receiver-Start

Der Receiver wird von der Weboberfläche im Normalbetrieb mit `--append` gestartet.

Damit werden bestehende Capture-Dateien nicht überschrieben.

### 4.3 Importer-Start

Der Importer wird mit `--follow` gestartet.

Der bestehende Checkpoint wird dabei normal verwendet. Optionen wie `--reset-checkpoint`, `--no-checkpoint` oder `--start-at-end` werden von der normalen Weboberfläche nicht automatisch gesetzt.

## 5. QuestDB

Die Weboberfläche prüft, ob QuestDB über die konfigurierte HTTP-Schnittstelle erreichbar ist.

Zusätzlich wird der letzte Paketzeitpunkt aus den vorhandenen Daten angezeigt.

Die Datenbankparameter werden in der lokalen `report_config.json` gepflegt.

## 6. Reports

Die Report-Erzeugung bleibt logisch von Receiver und Importer getrennt.

Die Weboberfläche übergibt:

- Repeatername oder kurzen Hash
- Beginn des Auswertungszeitraums
- Ende des Auswertungszeitraums

QuestDB-Host, Port und Receiver-Informationen werden aus der Konfiguration gelesen.

Die HTML-Dateinamen werden automatisch erzeugt.

## 7. Konfiguration

Produktive lokale Konfiguration:

```text
report_config.json
```

Vorlage im Repository:

```text
report_config.example.json
```

`report_config.json` sollte nicht versioniert werden, da sie standortspezifische Angaben enthalten kann.

## 8. Laufzeitdateien

Folgende Dateien sind Laufzeit-/Standortdaten und gehören normalerweise nicht ins Git-Repository:

```text
report_config.json
state/
logs/
reports/
packettap_capture.bin
packettap_capture.log
packettap_stream.bin
```

## 9. Windows und Linux

Der aktuelle Entwicklungsstand wurde unter Windows praktisch getestet.

Die zentralen Betriebsmechanismen sind plattformübergreifend ausgelegt:

```text
Single Instance:
  Windows -> msvcrt.locking()
  Linux   -> fcntl.flock()

Stop:
  Windows/Linux -> Stop-Datei

Weboberfläche:
  Python-Standardbibliothek
```

Für einen späteren Linux-Dauerbetrieb kann zusätzlich ein `systemd`-Service für die Weboberfläche vorgesehen werden. Receiver und Importer können dabei weiterhin dieselben Lock-/Stop-Mechanismen verwenden.

## 10. Designentscheidungen

### Lock-Dateien sind nicht nur Statusdateien

Der Inhalt der `.lock`-Datei enthält PID und Startzeit, maßgeblich ist aber der vom Betriebssystem gehaltene Dateilock.

Die Datei darf daher nach einem Prozessende weiterhin existieren. Ein vorhandener Dateiname allein bedeutet nicht, dass der Dienst läuft.

### Stop-Dateien sind Befehle

Eine `.stop`-Datei ist ein einmaliger Steuerbefehl. Der jeweilige Dienst entfernt sie beim geordneten Shutdown.

Beim Start wird eine eventuell übrig gebliebene alte Stop-Datei entfernt, damit eine neue Instanz nicht unmittelbar wieder beendet wird.

### Checkpoint-Datei ist persistenter Zustand

`state/importer.state` ist dagegen dauerhafter Zustand und darf beim normalen Stop oder Neustart nicht gelöscht werden.

Sie ist für die sichere Fortsetzung des Imports vorgesehen.
