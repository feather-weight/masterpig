# Masterpig Dev Bundle (Clean)

## Run
```bash
docker compose down --remove-orphans
docker compose up -d --build
```

Create a `.env` file in the project root with the following keys to configure
API access and the database:

```
TATUM_API_KEY=your-tatum-key
INFURA_PROJECT_ID=your-infura-project-id
MONGO_URI=your-mongodb-uri
MONGO_DB=MasterPig
```

Test:
```bash
curl -s http://localhost:3000/health
curl -s http://localhost:3000/stats | jq
curl -s http://localhost:3000/metrics | jq
```

Start/stop a demo scan:
```bash
curl -sS -X POST "http://localhost:3000/start_scan" --data-urlencode "xpub=demo-xpub" | jq
# optionally specify ?chain=eth to scan Ethereum xpubs
curl -s http://localhost:3000/stats | jq
curl -s http://localhost:3000/metrics | jq
curl -sS -X POST "http://localhost:3000/stop_scan" | jq
```

Landing page: http://localhost/
App UI:       http://localhost:3000/

## Derive extended keys

An interactive helper for generating extended private/public keys from
hexadecimal values is available:

```bash
python -m app.keygen
```

The script lets you supply a specific hex value, a range, or a set of
random values and prints the corresponding `tprv/uprv/xprv/yprv/zprv`
and `tpub/upub/xpub/ypub/zpub` keys. If Bitcoin or Ethereum scanning is
selected the resulting xpub is fed directly into the scanner.
