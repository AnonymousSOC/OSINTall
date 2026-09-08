#!/usr/bin/env python3
"""
OSINTALL - File, Image & Geolocation Analysis (GEOINT / IMINT) Module (Enhanced)
Covers: ExifTool Parser, Native PIL Metadata Engine, GPS to Decimal Conversion,
Interactive Offline/Standalone Leaflet.js HTML Map Generation, and Reverse Image Links.
"""

import os
import subprocess
import datetime
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
from rich.table import Table
from rich.panel import Panel
from modules.banner import (
    console, print_section, print_info, print_success, print_warning,
    print_error, is_tool_available
)

def dms_to_decimal(degrees, minutes, seconds, direction) -> float:
    """Converts Degrees, Minutes, Seconds to Decimal Degrees."""
    try:
        deg = float(degrees)
        min_val = float(minutes)
        sec = float(seconds)
        dec = deg + (min_val / 60.0) + (sec / 3600.0)
        if direction in ['S', 'W']:
            dec = -dec
        return round(dec, 6)
    except Exception:
        return 0.0

def generate_leaflet_map(lat: float, lon: float, file_name: str) -> str:
    """Generates a standalone, dark-mode Leaflet.js HTML map view for found GPS coordinates."""
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    reports_dir = os.path.join(base_dir, "reports")
    os.makedirs(reports_dir, exist_ok=True)
    
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    clean_name = os.path.splitext(os.path.basename(file_name))[0]
    clean_name = "".join(c for c in clean_name if c.isalnum() or c in ("-", "_"))
    map_path = os.path.join(reports_dir, f"geoint_map_{clean_name}_{timestamp}.html")

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GEOINT Map - {file_name}</title>
    <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
    <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
    <style>
        body, html {{ margin: 0; padding: 0; height: 100%; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0d1117; color: #c9d1d9; }}
        #header {{ padding: 12px 20px; background: #161b22; border-bottom: 1px solid #30363d; display: flex; justify-content: space-between; align-items: center; }}
        #header h2 {{ margin: 0; color: #58a6ff; font-size: 1.2rem; }}
        #header span {{ font-size: 0.9rem; color: #8b949e; }}
        #map {{ height: calc(100% - 50px); width: 100%; }}
        .leaflet-popup-content-wrapper {{ background: #161b22; color: #c9d1d9; border: 1px solid #30363d; }}
        .leaflet-popup-tip {{ background: #161b22; }}
    </style>
</head>
<body>
    <div id="header">
        <h2>📍 OSINTALL GEOINT Map Pin</h2>
        <span>File: <strong>{file_name}</strong> | Coordinates: <strong>{lat}, {lon}</strong></span>
    </div>
    <div id="map"></div>
    <script>
        const lat = {lat};
        const lon = {lon};
        const map = L.map('map').setView([lat, lon], 16);

        // Layers: OpenStreetMap and Satellite
        const osm = L.tileLayer('https://tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png', {{
            maxZoom: 19,
            attribution: '© OpenStreetMap'
        }}).addTo(map);

        const satellite = L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{{z}}/{{y}}/{{x}}', {{
            attribution: 'Esri Satellite'
        }});

        L.control.layers({{ "Street Map": osm, "Satellite View": satellite }}).addTo(map);

        const marker = L.marker([lat, lon]).addTo(map);
        marker.bindPopup("<b>Target Location</b><br>Latitude: " + lat + "<br>Longitude: " + lon + "<br><a href='https://www.google.com/maps?q=" + lat + "," + lon + "' target='_blank' style='color:#58a6ff;'>Open in Google Maps</a>").openPopup();
    </script>
</body>
</html>
"""
    try:
        with open(map_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        return map_path
    except Exception:
        return ""

def extract_exif(file_path: str) -> dict:
    """Extracts rich EXIF metadata and GPS coordinates from an image or file."""
    base_name = os.path.basename(file_path)
    print_section(f"GEOINT & IMINT: File & Image Analysis ({base_name})", icon="📸")
    
    if not os.path.exists(file_path):
        print_error(f"File not found: {file_path}")
        return {"error": "File not found"}

    meta = {
        "file_path": file_path,
        "file_name": base_name,
        "file_size": os.path.getsize(file_path),
        "tags": {},
        "gps": {},
        "device": {},
        "map_html_report": ""
    }

    # 1. Native PIL Metadata Parser
    try:
        with Image.open(file_path) as img:
            meta["format"] = img.format
            meta["dimensions"] = f"{img.width}x{img.height}"
            exif_data = img._getexif()
            if exif_data:
                gps_info = {}
                for tag_id, value in exif_data.items():
                    tag_name = TAGS.get(tag_id, tag_id)
                    if tag_name == "GPSInfo":
                        for t in value:
                            sub_tag = GPSTAGS.get(t, t)
                            gps_info[sub_tag] = value[t]
                    elif tag_name in ["Make", "Model", "Software", "DateTimeOriginal", "LensModel", "Artist"]:
                        meta["device"][tag_name] = str(value)
                    elif tag_name not in ["MakerNote", "UserComment"]:
                        meta["tags"][str(tag_name)] = str(value)[:100]

                # Parse GPS Coordinates
                if gps_info:
                    lat_dms = gps_info.get("GPSLatitude")
                    lat_ref = gps_info.get("GPSLatitudeRef", "N")
                    lon_dms = gps_info.get("GPSLongitude")
                    lon_ref = gps_info.get("GPSLongitudeRef", "E")

                    if lat_dms and lon_dms:
                        lat = dms_to_decimal(lat_dms[0], lat_dms[1], lat_dms[2], lat_ref)
                        lon = dms_to_decimal(lon_dms[0], lon_dms[1], lon_dms[2], lon_ref)
                        meta["gps"]["latitude"] = lat
                        meta["gps"]["longitude"] = lon
                        meta["gps"]["lat_ref"] = lat_ref
                        meta["gps"]["lon_ref"] = lon_ref
                        
                        maps_url = f"https://www.google.com/maps?q={lat},{lon}"
                        osm_url = f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=16/{lat}/{lon}"
                        
                        # Generate offline Leaflet.js HTML map
                        map_file = generate_leaflet_map(lat, lon, base_name)
                        if map_file:
                            meta["map_html_report"] = map_file

                        gps_panel = (
                            f"[bold yellow]Latitude:[/]  {lat} ({lat_ref})\n"
                            f"[bold yellow]Longitude:[/] {lon} ({lon_ref})\n\n"
                            f"[bold green]Google Maps:[/]     [underline cyan]{maps_url}[/]\n"
                            f"[bold green]OpenStreetMap:[/]   [underline cyan]{osm_url}[/]\n"
                            f"[bold green]Local Leaflet Map:[/] [underline yellow]{map_file}[/]"
                        )
                        console.print(Panel(gps_panel, title="[bold red]🎯 Embedded GPS Geolocation Found[/]", border_style="red"))
    except Exception as e:
        print_warning(f"PIL parser note: {e}")

    # 2. ExifTool CLI on Kali (if available, captures 100+ deep tags)
    if is_tool_available("exiftool"):
        try:
            res = subprocess.run(["exiftool", file_path], capture_output=True, text=True, timeout=8)
            if res.returncode == 0 and res.stdout:
                for line in res.stdout.splitlines():
                    if ":" in line:
                        k, v = line.split(":", 1)
                        k = k.strip()
                        v = v.strip()
                        if k in ["Camera Model Name", "Make", "Software", "Create Date", "GPS Position"]:
                            meta["device"][k] = v
        except Exception:
            pass

    # Display Device & Capture Details
    if meta["device"]:
        dev_table = Table(title="Device & Metadata Insights", border_style="cyan")
        dev_table.add_column("Attribute", style="bold yellow", width=22)
        dev_table.add_column("Value", style="white")
        for k, v in meta["device"].items():
            dev_table.add_row(k, v)
        console.print(dev_table)

    # 3. Reverse Image Search & Facial Recognition Toolkit
    table = Table(title="Reverse Image & Facial Recognition Engines (IMINT)", border_style="yellow")
    table.add_column("Engine / Tool", style="bold cyan", width=22)
    table.add_column("Purpose & Link", style="white")
    
    table.add_row("Google Lens", "https://lens.google.com/ (Visual Provenance & Object Matching)")
    table.add_row("Yandex Images", "https://yandex.com/images/ (Facial & Location Recognition)")
    table.add_row("TinEye", "https://tineye.com/ (Chronological Image Tracking)")
    table.add_row("PimEyes", "https://pimeyes.com/ (AI Face Search across Open Web)")
    table.add_row("FaceCheck.ID", "https://facecheck.id/ (Mugshot & Social Face Search)")
    table.add_row("SunCalc (Shadows)", "https://www.suncalc.org/ (Determine photo time by shadow angles)")
    table.add_row("Sentinel Hub EO", "https://apps.sentinel-hub.com/eo-browser/ (Satellite Imagery)")
    console.print(table)

    return meta
