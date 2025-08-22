import asyncio, random

THRESHOLDS = [1, 2, 5, 10, 50]

class Scanner:
    def __init__(self, max_gap=20, concurrency=16, follow_depth=2):
        self.max_gap = max_gap
        self.concurrency = concurrency
        self.follow_depth = follow_depth
        self._stop = False
        self.stats = {
            "addresses_scanned": 0,
            "active_addresses": 0,
            "with_balance": 0,
        }
        for t in THRESHOLDS:
            self.stats[f"tx_gt_{t}"] = 0

    async def scan_xpub(self, xpub: str):
        rng = random.Random(xpub)
        while not self._stop:
            await asyncio.sleep(0.3)
            self.stats["addresses_scanned"] += rng.randint(1, 3)
            self.stats["active_addresses"] += rng.randint(0, 1)
            if rng.random() < 0.3:
                self.stats["with_balance"] += 1
            for t in THRESHOLDS:
                if rng.random() < 0.2:
                    self.stats[f"tx_gt_{t}"] += 1
        return True

    def stop(self):
        self._stop = True
