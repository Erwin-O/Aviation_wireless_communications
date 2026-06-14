import re
import matplotlib.pyplot as plt
import os
import folium
import math
import itertools
from folium.plugins import TimestampedGeoJson

base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
log_file = os.path.join(base_dir, "logs", "mqtt_recorder.out")

positions = {}
current = {}

# -----------------------------
# PARSE LOG
# -----------------------------
with open(log_file, "r") as f:
    for line in f:
        line = line.strip()

        if line.startswith("FROM:"):
            current["from"] = line.split(":", 1)[1].strip()

        elif line.startswith("TIMESTAMP:"):
            current["ts"] = line.split(":", 1)[1].strip()

        elif line.startswith("HEADING:"):
            try:
                current["hdg"] = float(line.split(":", 1)[1].strip())
            except Exception:
                current["hdg"] = None

        elif line.startswith("POSITION:"):
            nums = re.findall(r"-?\d+(?:\.\d+)?", line)

            if len(nums) >= 2 and "from" in current:
                lat = float(nums[0])
                lon = float(nums[1])
                aircraft = current["from"]

                positions.setdefault(aircraft, []).append(
                    (lat, lon, current.get("ts"), current.get("hdg"))
                )

            current = {}

# -----------------------------
# SORT DATA
# -----------------------------
for ac in positions:
    positions[ac].sort(key=lambda x: x[2] or "")

# -----------------------------
# COLORS
# -----------------------------
colors = itertools.cycle(["blue", "red", "green", "purple", "orange"])
aircraft_colors = {ac: next(colors) for ac in positions}

# -----------------------------
# BUILD FEATURES
# -----------------------------
features = []

MIN_MOVE = 0.01  # threshold to avoid arrows when stationary

for aircraft, coords in positions.items():
    color = aircraft_colors[aircraft]
    last_point = None

    for lat, lon, ts, hdg in coords:
        if ts is None:
            continue

        # -----------------------------
        # DOT
        # -----------------------------
        features.append({
            "type": "Feature",
            "geometry": {
                "type": "Point",
                "coordinates": [lon, lat],
            },
            "properties": {
                "time": ts,
                "icon": "circle",
                "iconstyle": {
                    "fillColor": color,
                    "fillOpacity": 0.8,
                    "stroke": True,
                    "radius": 3
                },
            },
        })

        # -----------------------------
        # DIRECTION INDICATOR (offset dot)
        # -----------------------------
        if hdg is None:
            continue

        if last_point is None:
            last_point = (lat, lon)
            continue

        dist = math.hypot(lat - last_point[0], lon - last_point[1])
        if dist < MIN_MOVE:
            continue

        scale = 0.01

        dx = scale * math.sin(math.radians(hdg))
        dy = scale * math.cos(math.radians(hdg))

        features.append({
            "type": "Feature",
            "geometry": {
                "type": "Point",
                "coordinates": [lon + dx, lat + dy],
            },
            "properties": {
                "time": ts,
                "icon": "circle",
                "iconstyle": {
                    "fillColor": color,
                    "fillOpacity": 0.6,
                    "stroke": False,
                    "radius": 2
                },
            },
        })

        last_point = (lat, lon)


# -----------------------------
# MAP
# -----------------------------
first_aircraft = next(iter(positions.values()))
center_lat = first_aircraft[0][0]
center_lon = first_aircraft[0][1]

m = folium.Map(location=[center_lat, center_lon], zoom_start=8)

TimestampedGeoJson(
    {
        "type": "FeatureCollection",
        "features": features,
    },
    period="PT10S",
    add_last_point=True,
    auto_play=True,
    loop=False,
    max_speed=1,
    loop_button=True,
    time_slider_drag_update=True,
).add_to(m)

# -----------------------------
# TRAJECTORIES + MARKERS
# -----------------------------
for aircraft, coords in positions.items():
    color = aircraft_colors[aircraft]
    points = [(lat, lon) for lat, lon, _, _ in coords]

    folium.PolyLine(points, color=color, weight=3).add_to(m)

    folium.Marker(
        points[0],
        popup=f"{aircraft} START",
        icon=folium.Icon(color="green")
    ).add_to(m)

    folium.Marker(
        points[-1],
        popup=f"{aircraft} END",
        icon=folium.Icon(color="red")
    ).add_to(m)

# -----------------------------
# SAVE
# -----------------------------
output_file = "flight_map.html"
m.save(output_file)

print(f"Map saved to {output_file}")

# -----------------------------
# PLOT (IMPROVED ARROWS)
# -----------------------------
plt.figure(figsize=(10, 8))

for aircraft, coords in positions.items():
    lats = [c[0] for c in coords]
    lons = [c[1] for c in coords]

    plt.plot(lons, lats, linewidth=2, label=aircraft)

    last_point = None

    for lat, lon, _, hdg in coords:
        if hdg is None:
            continue

        if last_point is None:
            last_point = (lat, lon)
            continue

        dist = math.hypot(lat - last_point[0], lon - last_point[1])

        if dist < 0.01:
            continue

        scale = max(max(lats)-min(lats), max(lons)-min(lons)) * 0.05

        dx = scale * math.sin(math.radians(hdg))
        dy = scale * math.cos(math.radians(hdg))

        plt.arrow(lon, lat, dx, dy,
                  head_width=scale*0.05,
                  head_length=scale*0.03)

        last_point = (lat, lon)

    plt.scatter(lons[0], lats[0])
    plt.scatter(lons[-1], lats[-1])

plt.xlabel("Longitude")
plt.ylabel("Latitude")
plt.title("Flight Trajectories")
plt.legend()
plt.grid()
plt.show()