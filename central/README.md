# Sentinel Central

Central processor and management UI for a network of Sentinel sensors.

Each client keeps capturing into its local `packet.db`. When a client is reachable, this server copies **new** `Packet` rows into a central SQLite database and shows them in a local web UI (same look as SmartInbox).

## Layout

```
central/
  cli.py              serve / one-shot ingest
  db.py               central SQLite schema
  ingest.py           pull new rows from client packet.db files
  web/                FastAPI UI
  config.yaml         bind address, interval, optional client seed list
  data/               central database (created at runtime)
```

## Run

```bash
cd /home/bill/sentinel
pip install -r central/requirements.txt
python3 -m central serve
```

Open [http://127.0.0.1:8093](http://127.0.0.1:8093).

One-shot pull without the web UI:

```bash
python3 -m central ingest
```

## Clients

Register a client in the web UI (Clients page) or seed `config.yaml`:

```yaml
clients:
  - name: patio-pi
    db_path: /mnt/sentinel/patio/packet.db
    enabled: true
```

`db_path` is the path **this server** uses to open the client's SQLite file (NFS, SSHFS, a copied file, or a local sensor). If the file is missing, that client is marked offline and retried on the next interval.
