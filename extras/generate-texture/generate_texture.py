#!/usr/bin/env python3
"""Generate a composite globe texture for the mobile pane globe.

Downloads the blue marble earth texture from unpkg, draws neon green country
borders from countries.geojson on top, and saves the result as a single PNG.
This baked texture replaces polygon geometry on the mobile globe, reducing
memory usage on constrained devices (iOS Safari).

Usage:
    python generate_texture.py
"""

import json
import urllib.request
from pathlib import Path

from PIL import Image, ImageDraw
from shapely.geometry import shape

BLUE_MARBLE_URL = "https://unpkg.com/three-globe/example/img/earth-blue-marble.jpg"
GEOJSON_PATH = Path(__file__).parent / "static" / "countries.geojson"
OUTPUT_PATH = Path(__file__).parent / "static" / "earth-borders-mobile.jpg"
BORDER_COLOR = (0, 255, 65)  # #00ff41
BORDER_WIDTH = 2


def lon_lat_to_pixel(lon, lat, w, h):
    """Convert longitude/latitude to equirectangular pixel coordinates."""
    x = (lon + 180) / 360 * w
    y = (90 - lat) / 180 * h
    return x, y


def draw_ring(draw, ring, w, h):
    """Draw a single polygon ring (list of [lon, lat] coords) as connected lines."""
    coords = ring if isinstance(ring, list) else list(ring)
    if len(coords) < 2:
        return

    pixels = [lon_lat_to_pixel(lon, lat, w, h) for lon, lat in coords]

    # Draw line segments, skipping those that wrap around the antimeridian
    for i in range(len(pixels) - 1):
        x1, y1 = pixels[i]
        x2, y2 = pixels[i + 1]
        # Skip segments that span more than half the image width (antimeridian wrap)
        if abs(x2 - x1) > w * 0.5:
            continue
        draw.line([(x1, y1), (x2, y2)], fill=BORDER_COLOR, width=BORDER_WIDTH)


def draw_polygon(draw, polygon_coords, w, h):
    """Draw all rings of a polygon (exterior + holes)."""
    for ring in polygon_coords:
        draw_ring(draw, ring, w, h)


def main():
    # Download blue marble texture
    print(f"Downloading blue marble from {BLUE_MARBLE_URL}...")
    req = urllib.request.Request(BLUE_MARBLE_URL, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req) as resp:
        img_data = resp.read()

    from io import BytesIO
    img = Image.open(BytesIO(img_data)).convert("RGB")
    w, h = img.size
    print(f"Base image size: {w}x{h}")

    # Load GeoJSON
    print(f"Loading country borders from {GEOJSON_PATH}...")
    with open(GEOJSON_PATH) as f:
        geojson = json.load(f)

    draw = ImageDraw.Draw(img)

    count = 0
    for feature in geojson["features"]:
        geom = feature.get("geometry")
        if not geom:
            continue
        gtype = geom["type"]
        coords = geom["coordinates"]

        if gtype == "Polygon":
            draw_polygon(draw, coords, w, h)
            count += 1
        elif gtype == "MultiPolygon":
            for polygon_coords in coords:
                draw_polygon(draw, polygon_coords, w, h)
            count += 1

    print(f"Drew borders for {count} countries")

    # Save
    img.save(OUTPUT_PATH, "JPEG", quality=90)
    size_kb = OUTPUT_PATH.stat().st_size / 1024
    print(f"Saved to {OUTPUT_PATH} ({size_kb:.0f} KB)")


if __name__ == "__main__":
    main()
