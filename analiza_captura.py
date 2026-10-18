#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
analiza_captura.py
==================
Analiza una captura de red en formato .pcap (el mismo que abre NetworkMiner) y
automatiza todos los pasos de la practica "Analizando conexiones de red. Caso
DeepSeek". Si la captura esta en .pcapng, se puede convertir antes con:
    editcap -F pcap captura.pcapng captura.pcap

Que hace, paso a paso
---------------------
1. Elige el fichero de captura .pcap (argumento o ventana de seleccion).
2. Extrae con tshark, para la IP del dispositivo analizado:
     - los dominios consultados por DNS      -> dns_queries.txt
     - las IPs destino                       -> dst_ips.txt
     - los nombres SNI de las conexiones TLS -> sni_hosts.txt
3. Quita IPs privadas y duplicados, y cuenta cuantos paquetes hay por IP.
4. Geolocaliza cada IP publica (pais, region, ciudad, ISP) con ipwho.is.
5. Consulta la reputacion de cada IP en VirusTotal (opcional, necesita API key).
6. Genera los ficheros de salida:
     - geo_ips.csv      una fila por IP: pais, ISP, reputacion, paquetes
     - resumen.txt      resumen por pais y listado de IPs marcadas
     - informe.html     informe visual con mapa, paises, dominios y tabla

Requisitos
----------
  - Python 3.8 o superior
  - pip install requests
  - Wireshark instalado (incluye tshark). Se busca en el PATH y en
    C:\\Program Files\\Wireshark\\tshark.exe
  - (Opcional) API key gratuita de VirusTotal, en la variable de entorno
    VT_API_KEY o con --vt-key. NUNCA la escribas dentro del script.

Ejemplos de uso
---------------
  python analiza_captura.py                     # abre el selector de ficheros
  python analiza_captura.py deepseek.pcap --ip 192.168.137.156
  python analiza_captura.py deepseek.pcap --ip 192.168.137.156 --out resultados

Aviso
-----
Usalo solo sobre capturas propias o con autorizacion expresa. Una captura de
trafico contiene datos personales: guardala cifrada y borrala al terminar.
"""

from __future__ import annotations

import argparse
import csv
import html
import ipaddress
import json
import os
import shutil
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import requests

# --------------------------------------------------------------------------
# Constantes de configuracion
# --------------------------------------------------------------------------
TSHARK_WINDOWS = r"C:\Program Files\Wireshark\tshark.exe"  # ruta por defecto en Windows
GEO_URL = "https://ipwho.is/{}"                            # API de geolocalizacion
VT_URL = "https://www.virustotal.com/api/v3/ip_addresses/{}"

TIMEOUT_GEO = 10      # segundos de espera maxima por consulta de geolocalizacion
TIMEOUT_VT = 15       # idem para VirusTotal
PAUSA_GEO = 0.4       # pausa entre consultas de geolocalizacion (cortesia con la API)
PAUSA_VT = 16         # VirusTotal gratuito: 4 consultas/minuto -> 1 cada 15 s o mas


# --------------------------------------------------------------------------
# Utilidades de entrada: tshark y seleccion del fichero
# --------------------------------------------------------------------------
def buscar_tshark() -> str:
    """Devuelve la ruta de tshark.

    Primero lo busca en el PATH y, si no esta, en la ruta por defecto de
    Wireshark en Windows. Si no lo encuentra, termina el programa con un
    mensaje claro.
    """
    ruta = shutil.which("tshark")
    if ruta:
        return ruta
    if os.path.exists(TSHARK_WINDOWS):
        return TSHARK_WINDOWS
    sys.exit("No se encuentra tshark. Instala Wireshark o anade su carpeta al PATH.")


def elegir_fichero() -> str:
    """Abre una ventana para elegir la captura. Devuelve '' si se cancela."""
    import tkinter as tk
    from tkinter import filedialog

    raiz = tk.Tk()
    raiz.withdraw()  # ocultamos la ventana principal, solo queremos el dialogo
    return filedialog.askopenfilename(
        title="Selecciona la captura",
        filetypes=[("Captura PCAP", "*.pcap"), ("Todos", "*.*")],
    )


# --------------------------------------------------------------------------
# Extraccion con tshark
# --------------------------------------------------------------------------
def extraer_valores(tshark: str, pcap: str, filtro: str, campo: str) -> List[str]:
    """Ejecuta tshark sobre la captura y devuelve la lista de valores del campo.

    Equivale a:  tshark -r captura -Y "<filtro>" -T fields -e <campo>

    Detalle importante: cuando un paquete tiene varias cabeceras (por ejemplo
    un ICMP de error que lleva dentro la cabecera IP original), tshark escribe
    varios valores en la misma linea separados por comas, p. ej.
    '142.251.140.227,192.168.137.156'. Aqui se separan para que cada valor
    cuente como una entrada propia.
    """
    orden = [tshark, "-r", pcap, "-Y", filtro, "-T", "fields", "-e", campo]
    try:
        salida = subprocess.run(orden, capture_output=True, text=True, check=True).stdout
    except subprocess.CalledProcessError as error:
        sys.exit(f"tshark ha fallado con el filtro '{filtro}':\n{error.stderr.strip()}")

    valores: List[str] = []
    for linea in salida.splitlines():
        valores += [v.strip() for v in linea.split(",") if v.strip()]
    return valores


def es_publica(texto: str) -> bool:
    """True si el texto es una IP publica (no privada, ni local, ni multicast)."""
    try:
        return ipaddress.ip_address(texto).is_global
    except ValueError:
        return False


# --------------------------------------------------------------------------
# Consultas a servicios externos
# --------------------------------------------------------------------------
def geolocalizar(ip: str) -> Dict[str, str]:
    """Consulta ipwho.is y devuelve pais, region, ciudad, ISP y coordenadas.

    Si la consulta falla, devuelve campos vacios para no romper el resto del
    analisis. La geolocalizacion por IP es APROXIMADA: con CDN (Cloudflare,
    Akamai, CloudFront) el pais puede no corresponder al servidor real.
    """
    vacio = {"pais": "", "region": "", "ciudad": "", "isp": "", "lat": None, "lon": None}
    try:
        datos = requests.get(GEO_URL.format(ip), timeout=TIMEOUT_GEO).json()
        if datos.get("success"):
            return {
                "pais": datos.get("country_code", ""),
                "region": datos.get("region", ""),
                "ciudad": datos.get("city", ""),
                "isp": (datos.get("connection") or {}).get("isp", ""),
                "lat": datos.get("latitude"),
                "lon": datos.get("longitude"),
            }
        print(f"[!] ipwho.is {ip}: {datos.get('message')}")
    except (requests.RequestException, ValueError) as error:
        print(f"[!] Geolocalizacion {ip}: {error}")
    return vacio


def reputacion_vt(ip: str, clave: Optional[str], reintentar: bool = True) -> Optional[Tuple[int, int]]:
    """Consulta VirusTotal y devuelve (malicious, suspicious), o None si no hay datos.

    - Sin clave no se consulta nada.
    - Si VirusTotal responde 429 (demasiadas consultas), espera 60 s y reintenta una vez.
    - Una unica deteccion en una IP de CDN suele ser un falso positivo.
    """
    if not clave:
        return None
    try:
        r = requests.get(VT_URL.format(ip), headers={"x-apikey": clave}, timeout=TIMEOUT_VT)
        if r.status_code == 200:
            stats = r.json()["data"]["attributes"]["last_analysis_stats"]
            return stats.get("malicious", 0), stats.get("suspicious", 0)
        if r.status_code == 429 and reintentar:
            print("    Limite de VirusTotal alcanzado, espero 60 s...")
            time.sleep(60)
            return reputacion_vt(ip, clave, reintentar=False)
        print(f"[!] VirusTotal {ip}: HTTP {r.status_code}")
    except (requests.RequestException, KeyError, ValueError) as error:
        print(f"[!] VirusTotal {ip}: {error}")
    return None


# --------------------------------------------------------------------------
# Informe HTML con mapa
# --------------------------------------------------------------------------
PLANTILLA_HTML = """<!doctype html><html lang="es"><head><meta charset="utf-8">
<title>Informe {{TITULO}}</title>
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css">
<style>body{font-family:sans-serif;margin:2rem}#map{height:420px;margin:1rem 0}
table{border-collapse:collapse}td,th{border:1px solid #888;padding:4px 8px}
.mal{background:#fdd}</style></head><body>
<h1>Informe de captura: {{TITULO}}</h1><p>Dispositivo analizado: {{IP}}</p>
<div id="map"></div>
<h2>Paises</h2><ul>{{PAISES}}</ul>
<h2>Dominios mas consultados (DNS + SNI)</h2><ul>{{DOMINIOS}}</ul>
<h2>IPs destino</h2>
<table><tr><th>IP</th><th>Paquetes</th><th>Pais</th><th>Ciudad</th><th>ISP</th><th>VirusTotal</th></tr>{{FILAS}}</table>
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<script>var PUNTOS={{PUNTOS}};
var m=L.map('map').setView([30,10],2);
L.tileLayer('https://tile.openstreetmap.org/{z}/{x}/{y}.png',{attribution:'OpenStreetMap'}).addTo(m);
PUNTOS.forEach(function(p){L.circleMarker([p.lat,p.lon],{color:p.mal?'red':'blue'}).addTo(m).bindPopup(p.txt);});
</script></body></html>"""


def generar_html(filas: List[dict], dominios: Counter, pcap: str, ip_dispositivo: str) -> str:
    """Construye el informe HTML (mapa Leaflet, paises, dominios y tabla de IPs).

    Todo el texto externo (ISP, ciudades...) se escapa con html.escape para
    que ningun dato de la captura pueda inyectar codigo en el informe.
    """
    esc = html.escape
    tabla = "".join(
        f"<tr class='{'mal' if f['marcada'] else ''}'><td>{esc(f['ip'])}</td><td>{f['paquetes']}</td>"
        f"<td>{esc(f['pais'])}</td><td>{esc(f['ciudad'])}</td><td>{esc(f['isp'])}</td>"
        f"<td>{esc(f['vt'])}</td></tr>"
        for f in filas
    )
    paises = "".join(
        f"<li>{esc(p)}: {n}</li>" for p, n in Counter(f["pais"] or "?" for f in filas).most_common()
    )
    doms = "".join(f"<li>{esc(d)} ({n})</li>" for d, n in dominios.most_common(30))
    puntos = [
        {"lat": f["lat"], "lon": f["lon"], "mal": f["marcada"],
         "txt": f"{f['ip']} - {f['isp']} ({f['ciudad']}, {f['pais']})"}
        for f in filas if f["lat"] is not None
    ]
    # Se evita que '</script>' dentro de un dato cierre el bloque de script.
    puntos_js = json.dumps(puntos).replace("</", "<\\/")

    return (PLANTILLA_HTML
            .replace("{{TITULO}}", esc(Path(pcap).name))
            .replace("{{IP}}", esc(ip_dispositivo))
            .replace("{{PAISES}}", paises)
            .replace("{{DOMINIOS}}", doms)
            .replace("{{FILAS}}", tabla)
            .replace("{{PUNTOS}}", puntos_js))


# --------------------------------------------------------------------------
# Programa principal
# --------------------------------------------------------------------------
def main() -> None:
    ap = argparse.ArgumentParser(
        description="Analisis automatico de una captura de red (DNS, IPs, SNI, paises, reputacion)")
    ap.add_argument("pcap", nargs="?", help="captura en formato .pcap (si se omite se abre un selector)")
    ap.add_argument("--ip", help="IP del dispositivo analizado (p. ej. 192.168.137.156)")
    ap.add_argument("--vt-key", default=os.environ.get("VT_API_KEY"),
                    help="API key de VirusTotal (o variable de entorno VT_API_KEY)")
    ap.add_argument("--out", help="carpeta de salida (por defecto resultados_<captura>)")
    ap.add_argument("--sep", default=",", help="separador del CSV (usa ';' para Excel en espanol)")
    args = ap.parse_args()

    # 1) Entrada: captura, IP del dispositivo y carpeta de salida
    pcap = args.pcap or elegir_fichero()
    if not pcap or not os.path.isfile(pcap):
        sys.exit("No se ha seleccionado ninguna captura valida.")
    extension = Path(pcap).suffix.lower()
    if extension == ".pcapng":
        print("[i] Es un .pcapng. tshark lo lee igualmente, pero para trabajar con .pcap "
              "(y abrirlo en NetworkMiner) conviertelo con: editcap -F pcap captura.pcapng captura.pcap")
    elif extension != ".pcap":
        sys.exit(f"Formato no reconocido ({extension}). Usa una captura .pcap")
    ip = args.ip or input("IP del dispositivo (p. ej. 192.168.137.156): ").strip()
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        sys.exit(f"'{ip}' no es una IP valida.")
    carpeta = Path(args.out or f"resultados_{Path(pcap).stem}")
    carpeta.mkdir(exist_ok=True)
    tshark = buscar_tshark()

    # 2) Extraccion con tshark
    print("[1/4] Extrayendo datos con tshark...")
    dns = extraer_valores(tshark, pcap, f"dns.flags.response==0 && ip.src=={ip}", "dns.qry.name")
    destinos = extraer_valores(tshark, pcap, f"ip && ip.src=={ip}", "ip.dst")
    sni = extraer_valores(tshark, pcap,
                          f"tls.handshake.extensions_server_name && ip.src=={ip}",
                          "tls.handshake.extensions_server_name")
    for nombre, datos in (("dns_queries.txt", dns), ("dst_ips.txt", destinos), ("sni_hosts.txt", sni)):
        (carpeta / nombre).write_text("\n".join(datos), encoding="utf-8")

    # 3) Solo IPs publicas, con el numero de paquetes de cada una
    paquetes = Counter(d for d in destinos if es_publica(d))
    print(f"    {len(dns)} consultas DNS, {len(paquetes)} IPs publicas unicas, {len(sni)} SNI")
    if not paquetes:
        sys.exit("No hay IPs publicas en la captura. Revisa la IP del dispositivo y la interfaz capturada.")

    # 4) Geolocalizacion y reputacion
    print("[2/4] Geolocalizando y [3/4] comprobando reputacion...")
    filas: List[dict] = []
    for n, (direccion, cuenta) in enumerate(paquetes.most_common(), 1):
        fila = {"ip": direccion, "paquetes": cuenta, **geolocalizar(direccion)}
        rep = reputacion_vt(direccion, args.vt_key)
        fila["vt_mal"] = "" if rep is None else rep[0]
        fila["vt_sus"] = "" if rep is None else rep[1]
        fila["vt"] = "sin datos" if rep is None else f"{rep[0]} malicious / {rep[1]} suspicious"
        fila["marcada"] = bool(rep and (rep[0] > 0 or rep[1] > 0))
        filas.append(fila)
        print(f"    [{n}/{len(paquetes)}] {direccion:16} {fila['pais']:3} {fila['isp'][:30]:30} | {fila['vt']}")
        time.sleep(PAUSA_VT if args.vt_key else PAUSA_GEO)

    # 5) Ficheros de salida
    print("[4/4] Generando ficheros de salida...")
    with open(carpeta / "geo_ips.csv", "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f, delimiter=args.sep)
        w.writerow(["IP", "Paquetes", "Country", "Region", "City", "ISP", "VT_malicious", "VT_suspicious"])
        for r in filas:
            w.writerow([r["ip"], r["paquetes"], r["pais"], r["region"], r["ciudad"], r["isp"],
                        r["vt_mal"], r["vt_sus"]])

    por_pais: Dict[str, List[dict]] = {}
    for r in filas:
        por_pais.setdefault(r["pais"] or "?", []).append(r)
    lineas = ["RESUMEN POR PAIS", "=" * 40]
    for pais, grupo in sorted(por_pais.items(), key=lambda x: -len(x[1])):
        isps = ", ".join(sorted({g["isp"] for g in grupo if g["isp"]}))
        lineas.append(f"{pais}: {len(grupo)} IPs, {sum(g['paquetes'] for g in grupo)} paquetes | {isps}")
    marcadas = [r["ip"] for r in filas if r["marcada"]]
    lineas += ["", "IPs con detecciones en VirusTotal: " + (", ".join(marcadas) or "ninguna")]
    (carpeta / "resumen.txt").write_text("\n".join(lineas), encoding="utf-8")

    dominios = Counter(d.lower() for d in dns + sni)
    (carpeta / "informe.html").write_text(generar_html(filas, dominios, pcap, ip), encoding="utf-8")

    print("\n" + "\n".join(lineas))
    print(f"\nListo. Resultados en: {carpeta.resolve()}")


if __name__ == "__main__":
    main()
