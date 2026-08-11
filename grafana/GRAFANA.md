# Grafana -- Hinweise und Abhängigkeiten

## Zweck

Dieses Verzeichnis enthält die Grafana-Dashboards für die Auswertung der
mit MeshCore PacketTap erfassten und in QuestDB gespeicherten Daten.

Die Dashboards werden als JSON exportiert und unter
`grafana/dashboards/` im Repository abgelegt.

## Datenquelle

Die Dashboards verwenden QuestDB als Grafana-Datenquelle. Nach dem
Import eines Dashboards muss auf der jeweiligen Grafana-Installation
eine funktionierende QuestDB-Datasource vorhanden und dem Dashboard
zugeordnet sein.

## Zusätzlich benötigtes Grafana-Plugin

Für einige Visualisierungen wird das Plugin **Apache ECharts Panel** von
Volkov Labs benötigt.

**Plugin-ID:**

``` text
volkovlabs-echarts-panel
```

Ohne dieses Plugin können betroffene Panels nicht geladen werden.
Grafana zeigt dann beispielsweise:

``` text
Plugin volkovlabs-echarts-panel not found
```

Aktuell betrifft dies unter anderem das Panel:

-   `Kanalbelegung (Airtime) je Repeater`

sowie ein weiteres Dashboard-Panel, das ebenfalls auf dem ECharts-Panel
basiert.

## Installation

Das Plugin muss auf der Grafana-Instanz installiert werden, auf der die
Dashboards verwendet werden.

Bei einer klassischen Grafana-Installation kann es mit der Grafana-CLI
installiert werden:

``` bash
grafana cli plugins install volkovlabs-echarts-panel
```

Abhängig von der Grafana-Version bzw. Installationsart kann auch
folgender Aufruf verwendet werden:

``` bash
grafana-cli plugins install volkovlabs-echarts-panel
```

Anschließend Grafana neu starten.

Bei Docker-Installationen sollte das Plugin über die
Plugin-Konfiguration des Containers installiert werden, damit es nach
einem Neuaufbau des Containers weiterhin vorhanden ist.

## Dashboard-Import

Beim Übertragen der Dashboards auf eine neue Grafana-Installation
folgende Reihenfolge beachten:

1.  QuestDB-Datasource in Grafana einrichten.
2.  `volkovlabs-echarts-panel` installieren.
3.  Grafana gegebenenfalls neu starten.
4.  Dashboard-JSON aus `grafana/dashboards/` importieren.
5.  QuestDB-Datasource beim Import auswählen bzw. zuordnen.
6.  Prüfen, ob alle Panels ohne Plugin- oder Datasource-Fehler geladen
    werden.

## Projektregel

Dashboard-Abhängigkeiten von zusätzlichen Grafana-Plugins sollen in
dieser Datei dokumentiert werden. Dadurch lässt sich eine neue
PacketTap-/Grafana-Installation reproduzierbar aufsetzen.
