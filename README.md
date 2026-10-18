# analiza\_captura

Script en Python que automatiza el análisis de una captura de red en formato **`.pcap`** hecha con Wireshark: extrae los dominios y destinos con los que se comunica un dispositivo, geolocaliza las IPs, comprueba su reputación en VirusTotal y genera un informe con mapa.

Nace de la práctica *«Analizando conexiones de red. Caso DeepSeek»* del Curso de Especialización en Ciberseguridad en Entornos de las Tecnologías de la Información (CETI), y sirve para ver **con quién habla una app** (por ejemplo, una IA) sin descifrar su tráfico, solo con metadatos.

> \*\*Uso exclusivamente educativo.\*\* Úsalo solo sobre capturas de tu propia red o con autorización expresa. Una captura contiene datos personales: guárdala cifrada y bórrala al terminar.

## Qué hace

1. Te deja elegir la captura (o la recibe por argumento).
2. Con **tshark** extrae, para la IP del dispositivo:

   * dominios consultados por **DNS**,
   * **IPs destino**,
   * nombres **SNI** de las conexiones TLS.
3. Descarta IPs privadas y duplicados, y cuenta los paquetes por IP.
4. **Geolocaliza** cada IP pública (país, región, ciudad, ISP) con [ipwho.is](https://ipwho.is).
5. Consulta su **reputación** en [VirusTotal](https://www.virustotal.com) (opcional).
6. Genera los resultados.

## Requisitos

* Python 3.8 o superior
* `pip install requests`
* [Wireshark](https://www.wireshark.org/) instalado (incluye `tshark`). El script lo busca en el `PATH` y en `C:\\Program Files\\Wireshark\\tshark.exe`.
* *(Opcional)* una API key gratuita de VirusTotal.

## Uso

```bash
# Abre un selector para elegir la captura
python analiza\_captura.py

# Indicando captura y dispositivo
python analiza\_captura.py deepseek.pcap --ip 192.168.137.156

# Con carpeta de salida propia y CSV para Excel en español
python analiza\_captura.py deepseek.pcap --ip 192.168.137.156 --out resultados --sep ";"
```

### Opciones

|Opción|Descripción|
|-|-|
|`pcap`|Captura `.pcap` a analizar. Si se omite, se abre un selector de ficheros.|
|`--ip`|IP del dispositivo analizado. Si se omite, la pide por teclado.|
|`--vt-key`|API key de VirusTotal. También se lee de la variable `VT\_API\_KEY`.|
|`--out`|Carpeta de salida. Por defecto `resultados\_<captura>`.|
|`--sep`|Separador del CSV (`,` por defecto; `;` si lo abres en Excel en español).|

### API key de VirusTotal

**No escribas nunca la clave en el código ni la subas a GitHub.** Pásala por variable de entorno:

```powershell
# Windows (PowerShell, solo para esta sesión)
$env:VT\_API\_KEY = "tu\_clave"
```

```bash
# Linux / macOS
export VT\_API\_KEY="tu\_clave"
```

Sin clave, el script funciona igual pero sin la parte de reputación. La cuenta gratuita permite 4 consultas por minuto, así que el script espera 16 segundos entre IPs (24 IPs ≈ 6-7 minutos).

## Ficheros que genera

|Fichero|Contenido|
|-|-|
|`dns\_queries.txt`|Dominios consultados por DNS|
|`dst\_ips.txt`|IPs destino (sin deduplicar)|
|`sni\_hosts.txt`|Nombres SNI de las conexiones TLS|
|`geo\_ips.csv`|Una fila por IP: paquetes, país, región, ciudad, ISP y reputación|
|`resumen.txt`|Resumen por país e IPs marcadas en VirusTotal|
|`informe.html`|Informe visual con mapa, países, dominios y tabla|

Ejemplo de `resumen.txt`:

```
RESUMEN POR PAIS
========================================
ES: 16 IPs, 1450 paquetes | Akamai Technologies, Inc., Apple Inc., Google LLC, Zenlayer Inc
US: 5 IPs, 310 paquetes | Amazon.com, Inc., Apple Inc., Cloudflare, Inc., Google LLC
...
IPs con detecciones en VirusTotal: 104.18.94.41
```



## Cómo capturar el tráfico

1. Windows: Ajustes → Red e Internet → **Zona con cobertura inalámbrica móvil** y conecta el móvil.
2. Abre Wireshark **como administrador** y captura en la interfaz del hotspot (la que tenga la IP `192.168.137.1`).
3. Con la captura en marcha, usa la app en el móvil.
4. Detén la captura y guárdala como **`.pcap`** (*Guardar como* → tipo «Wireshark/tcpdump… pcap»). Si ya la tienes en `.pcapng`: `editcap -F pcap captura.pcapng captura.pcap`.

## Notas y limitaciones

* **La geolocalización por IP es aproximada.** Con CDN (Cloudflare, Akamai, CloudFront) el país puede no corresponder al del servidor real ni al de la empresa propietaria.
* Una IP «limpia» en VirusTotal **no** demuestra que el servicio sea inofensivo, solo que no está reportada. Una única detección en una IP de CDN suele ser un falso positivo.
* El SNI va en claro en el ClientHello de TLS (1.2 y 1.3) salvo que el servidor use **ECH** (Encrypted Client Hello). Con DNS cifrado (DoH/DoT) tampoco aparecerán las consultas DNS.
* Las líneas donde tshark devuelve varios valores (`a,b`) se separan automáticamente.
* Para abrir `geo\_ips.csv` en Excel, usa *Datos → Obtener datos → Desde texto o CSV* con la detección de tipos desactivada; si no, Excel puede interpretar algunas IPs como números.

## Estructura del código

|Función|Qué hace|
|-|-|
|`buscar\_tshark()`|Localiza tshark en el PATH o en la ruta por defecto de Windows|
|`elegir\_fichero()`|Selector gráfico de la captura|
|`extraer\_valores()`|Ejecuta tshark con un filtro y devuelve los valores de un campo|
|`es\_publica()`|Filtra IPs privadas, locales y multicast|
|`geolocalizar()`|Consulta ipwho.is|
|`reputacion\_vt()`|Consulta VirusTotal con reintento si hay límite de uso|
|`generar\_html()`|Construye el informe con mapa (Leaflet)|
|`main()`|Orquesta todo el proceso|

## Autor

**OTHMANE ABED KHATTABI** · CETI, curso 2026-2027 

