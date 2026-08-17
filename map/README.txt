# PacketTap Offline-Karte

Verzeichnisstruktur:

map/
  leaflet/
    leaflet.css
    leaflet.js
    images/        optional, falls das Leaflet-CSS Markerbilder referenziert
  tiles/
    {z}/{x}/{y}.png

`report_server_v0.13.py` liefert alles unter `/map/` lokal aus.

Der Mesh Report v0.3 verwendet:

- `/map/leaflet/leaflet.css`
- `/map/leaflet/leaflet.js`
- `/map/tiles/{z}/{x}/{y}.png`

Die eigentlichen Kartenkacheln sind bewusst nicht Bestandteil dieses Pakets.
Verwende einen Tile-Datensatz, dessen Lizenz Offline-/Self-Hosting erlaubt.
