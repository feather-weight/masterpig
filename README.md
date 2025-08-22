# Masterpig Dev Bundle (Clean)

## Run
```bash
docker compose down --remove-orphans
docker compose up -d --build
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
curl -s http://localhost:3000/stats | jq
curl -s http://localhost:3000/metrics | jq
curl -sS -X POST "http://localhost:3000/stop_scan" | jq
```

Landing page: http://localhost/
App UI:       http://localhost:3000/
