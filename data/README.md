# USARE data directory

## `nmap-service-probes`

Service detection can use Nmap’s full probe database (thousands of signatures).

**Option A — copy from an existing Nmap install**

- Windows: `C:\Program Files (x86)\Nmap\nmap-service-probes` or `C:\Program Files\Nmap\nmap-service-probes`
- Linux: `/usr/share/nmap/nmap-service-probes`

Copy the file to:

`data/nmap-service-probes`

(next to this README, in the USARE project root `data/` folder)

**Option B — environment variable**

Set `USARE_NMAP_PROBES_FILE` to the full path of `nmap-service-probes` on your system.

USARE searches: env override → `data/nmap-service-probes` → standard Linux paths → common Windows Nmap paths.

The file is part of the Nmap project (GPL). Install Nmap or obtain the file from your distribution; do not use it against networks without authorization.
