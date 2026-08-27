#!/usr/bin/env python3
"""
OSINTALL - File, Image & Geolocation Analysis (GEOINT / IMINT) Module
Covers: ExifTool Metadata Parser, GPS to Decimal & Map Coordinates,
Reverse Image Search (Google Lens, Yandex, TinEye, PimEyes, FaceCheck.ID),
Geospatial Tools (Sentinel Hub, DualMaps, Google Earth Pro), SunCalc Shadow Calculation.
"""

import os
import subprocess
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
from rich.table import Table
from rich.panel import Panel
from modules.banner import console, print_section, print_info, print_success, print_warning, print_error

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

def extract_exif(file_path: str) -> dict:
    """Extracts EXIF metadata and GPS coordinates from an image."""
    print_section(f"GEOINT & IMINT: File & Image Analysis ({os.path.basename(file_path)})", icon="📸")
    
    if not os.path.exists(file_path):
        print_error(f"File not found: {file_path}")
        return {"error": "File not found"}

    meta = {"file_path": file_path, "tags": {}, "gps": {}}

    # 1. Try ExifTool CLI if available on Kali
    try:
        res = subprocess.run(["exiftool", file_path], capture_output=True, text=True, timeout=8)
        if res.returncode == 0 and res.stdout:
            print_success("Extracted metadata via [bold green]ExifTool[/]:")
            exif_table = Table(title="ExifTool Metadata Output", border_style="cyan")
            exif_table.add_column("Tag Name", style="bold yellow", width=25)
            exif_table.add_column("Value", style="white")
            
            for line in res.stdout.splitlines()[:25]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    meta["tags"][k.strip()] = v.strip()
                    exif_table.add_row(k.strip(), v.strip())
            console.print(exif_table)
            
            # Check for GPS in exiftool output
            for k, v in meta["tags"].items():
                if "GPS Position" in k or "GPS Coordinates" in k:
                    print_success(f"[bold red]GPS Coordinates Located:[/] {v}")
    except Exception:
        pass

    # 2. Extract using PIL as reliable native Python engine
    try:
        with Image.open(file_path) as img:
            exif_data = img._getexif()
            if exif_data:
                gps_info = {}
                for tag_id, value in exif_data.items():
                    tag_name = TAGS.get(tag_id, tag_id)
                    if tag_name == "GPSInfo":
                        for t in value:
                            sub_tag = GPSTAGS.get(t, t)
                            gps_info[sub_tag] = value[t]
                    elif tag_name not in ["MakerNote", "UserComment"]:
                        meta["tags"][str(tag_name)] = str(value)

                # Parse GPS
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
                        
                        maps_url = f"https://www.google.com/maps?q={lat},{lon}"
                        osm_url = f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=16/{lat}/{lon}"
                        dualmaps_url = f"http://dualmaps.com/map.htm?lat={lat}&lng={lon}"
                        
                        gps_panel = (
                            f"[bold yellow]Latitude:[/]  {lat} ({lat_ref})\n"
                            f"[bold yellow]Longitude:[/] {lon} ({lon_ref})\n\n"
                            f"[bold green]Google Maps:[/] [underline cyan]{maps_url}[/]\n"
                            f"[bold green]OpenStreetMap:[/] [underline cyan]{osm_url}[/]\n"
                            f"[bold green]DualMaps 3-in-1:[/] [underline cyan]{dualmaps_url}[/]"
                        )
                        console.print(Panel(gps_panel, title="[bold red]🎯 Embedded GPS Geolocation Found[/]", border_style="red"))
    except Exception as e:
        print_warning(f"PIL EXIF parser note: {e}")

    # 3. Reverse Image Search & Facial Recognition Toolkit
    table = Table(title="Reverse Image & Facial Recognition Engines (IMINT)", border_style="yellow")
    table.add_column("Engine / Tool", style="bold cyan", width=22)
    table.add_column("Purpose & Link", style="white")
    
    table.add_row("Google Lens", "https://lens.google.com/ (Visual Provenance / Object Matching)")
    table.add_row("Yandex Images", "https://yandex.com/images/ (High-accuracy Face & Location Matching)")
    table.add_row("TinEye", "https://tineye.com/ (Chronological Image Tracking & Historical Sources)")
    table.add_row("PimEyes", "https://pimeyes.com/ (AI Face Search across the Open Web)")
    table.add_row("FaceCheck.ID", "https://facecheck.id/ (Facial Recognition against Public mugshots/socials)")
    table.add_row("SunCalc (Solar Shadows)", "https://www.suncalc.org/ (Determine photo time/date by shadow angles)")
    table.add_row("Sentinel Hub EO Browser", "https://apps.sentinel-hub.com/eo-browser/ (Satellite Imagery & IR Bands)")
    table.add_row("Google Earth Pro", "https://earth.google.com/web/ (3D Topographic & Historical Satellite View)")
    table.add_row("FOCA Metadata Tool", "https://github.com/ElevenPaths/FOCA (Batch Office & PDF Metadata Scanner)")
    console.print(table)

    return meta
