# Tools

Dieses Verzeichnis enthält Hilfs-, Diagnose- und Wartungsskripte für
**MeshCore PacketTap**.

Die Skripte sind **nicht Bestandteil des normalen Dauerbetriebs**. Sie
werden nur bei Bedarf manuell verwendet, zum Beispiel zur Analyse von
Capture-Dateien oder für kontrollierte Backfill-Arbeiten in QuestDB.

## Wichtig: Start aus dem Repository-Hauptverzeichnis

Die Tools importieren Module aus dem Hauptverzeichnis des Projekts,
unter anderem:

-   `meshcore_decoder.py`
-   `mc_db.py`
-   `mc_writer.py`

Die Skripte müssen deshalb **aus dem Root-Verzeichnis des Repositorys**
gestartet werden.

Beispiel unter Windows:

``` powershell
cd C:\Pfad\zu\meshcore-packettap

python tools\analyze_capture.py --help
python tools\find_advert.py --help
python tools\backfill_discover_resp.py --help
python tools\backfill_mc_rx_repeater.py --help
```

Unter Linux entsprechend:

``` bash
cd /pfad/zu/meshcore-packettap

python tools/analyze_capture.py --help
python tools/find_advert.py --help
python tools/backfill_discover_resp.py --help
python tools/backfill_mc_rx_repeater.py --help
```

Nicht empfohlen ist der direkte Start aus dem `tools`-Verzeichnis:

``` powershell
cd tools
python analyze_capture.py
```

Dabei können die Imports der PacketTap-Module aus dem
Repository-Hauptverzeichnis fehlschlagen.

## Enthaltene Tools

### `analyze_capture.py`

Analysiert die von `receiver.py` erzeugte `packettap_capture.log`.

Das Werkzeug kann PacketTap-Datensätze dekodieren und wichtige
Informationen zu empfangenen MeshCore-Paketen ausgeben. Es eignet sich
insbesondere zur manuellen Diagnose von Capture-Daten.

### `find_advert.py`

Sucht ADVERT-Pakete anhand eines Node-Namens bzw. eines Teils des
Namens.

Für gefundene Adverts werden unter anderem Routing-, Regions-, RSSI- und
SNR-Informationen ausgegeben.

### `backfill_discover_resp.py`

Werkzeug zum nachträglichen Einlesen historischer
`DISCOVER_RESP`-Beobachtungen aus einer PacketTap-Capture-Datei in
`mc_contact_observations`.

Das Skript verändert weder `mc_rx` noch `mc_contacts` und greift nicht
in den Importer-Checkpoint ein.

Vor einem tatsächlichen Backfill sollte das Werkzeug zunächst mit
`--dry-run` geprüft werden.

Beispiel:

``` powershell
python tools\backfill_discover_resp.py --dry-run
```

### `backfill_mc_rx_repeater.py`

Werkzeug zum nachträglichen Ergänzen historischer
`mc_rx.repeater`-Zuordnungen für geeignete Pakete.

Das Skript arbeitet standardmäßig ohne Änderungen an QuestDB. Erst mit
`--apply` werden die ermittelten Änderungen tatsächlich ausgeführt.

Daher sollte zunächst immer der Standard-/Dry-Run verwendet und das
Ergebnis kontrolliert werden.

### `test_advert_decode.py`

Manuelles Diagnosewerkzeug zum Dekodieren und Anzeigen von
ADVERT-Paketen aus einer PacketTap-Capture-Datei.

Trotz des Dateinamens handelt es sich derzeit nicht um einen
automatisierten Unit-Test, sondern um ein manuell verwendetes
Analysewerkzeug.

## Sicherheit bei Backfill-Werkzeugen

Die Backfill-Skripte dienen der gezielten Korrektur bzw. Ergänzung
historischer Daten.

Vor Änderungen an einer produktiven QuestDB sollten:

1.  die im Dry-Run angezeigten Kandidaten geprüft werden,
2.  die verwendete Capture-Datei kontrolliert werden,
3.  Host und Port der Ziel-QuestDB überprüft werden,
4.  nach Möglichkeit eine Sicherung der betroffenen Daten vorhanden
    sein.

Die Backfill-Werkzeuge sollten nicht Bestandteil eines automatischen
PacketTap-Starts oder Dauerbetriebs sein.
