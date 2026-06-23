# arista_hybrid.py - نسخه نهایی فوق‌سریع

import asyncio
import aiohttp
import ipaddress
import random
import json
import time
import os
import logging
import socket
from dataclasses import dataclass
from typing import List, Dict, Optional, Any, Tuple
from collections import OrderedDict
import multiprocessing
from concurrent.futures import ThreadPoolExecutor
import aiosqlite

try:
    import maxminddb
    HAS_MAXMIND = True
except ImportError:
    HAS_MAXMIND = False

try:
    import uvloop
    HAS_UVLOOP = True
except ImportError:
    HAS_UVLOOP = False

if HAS_UVLOOP:
    uvloop.install()

@dataclass
class Config:
    max_workers: int = 4
    queue_size: int = 20000
    batch_size: int = 500
    tcp_timeout: float = 0.3
    max_latency: int = 200
    min_latency: int = 1
    db_path: str = "proxies_hybrid.db"
    max_output_ips: int = 4000
    retention_days: int = 7
    maxmind_path: str = "GeoLite2-Country.mmdb"
    enable_http_test: bool = False
    enable_prometheus: bool = False
    runner_id: str = None
    ports: List[int] = None
    quality_threshold: int = 200
    geo_thread_pool: int = 2

    def __post_init__(self):
        if self.ports is None:
            self.ports = [443, 8443, 8080, 80]
        if self.runner_id is None:
            self.runner_id = f"runner-{os.getpid()}-{int(time.time())}"

class FastTCPScanner:
    def __init__(self, max_concurrent: int = 200):
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.failed_cache = {}
        self.failed_cache_ttl = 60
    
    async def check_port_fast(self, ip: str, port: int, timeout: float = 0.3) -> Tuple[Optional[int], Optional[float]]:
        try:
            loop = asyncio.get_event_loop()
            start = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setblocking(False)
            fut = loop.sock_connect(sock, (ip, port))
            try:
                await asyncio.wait_for(fut, timeout=timeout)
                latency = (time.time() - start) * 1000
                sock.close()
                return port, latency
            except:
                sock.close()
                return port, None
        except:
            return port, None
    
    async def scan_ip_parallel(self, ip: str, ports: List[int], timeout: float = 0.3, min_latency: int = 1, max_latency: int = 200) -> Tuple[Optional[int], Optional[float]]:
        if ip in self.failed_cache:
            if time.time() - self.failed_cache[ip] < self.failed_cache_ttl:
                return None, None
        
        async def check_port(port):
            async with self.semaphore:
                return await self.check_port_fast(ip, port, timeout)
        
        tasks = [check_port(p) for p in ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        best_port = None
        best_latency = None
        
        for result in results:
            if isinstance(result, Exception):
                continue
            port, latency = result
            if latency is not None and min_latency <= latency <= max_latency:
                if best_latency is None or latency < best_latency:
                    best_latency = latency
                    best_port = port
                    break
        
        if best_port is None:
            self.failed_cache[ip] = time.time()
            if len(self.failed_cache) > 5000:
                keys = list(self.failed_cache.keys())
                for k in keys[:2500]:
                    del self.failed_cache[k]
        
        return best_port, best_latency
    
    async def scan_batch(self, ips: List[str], ports: List[int], timeout: float = 0.3, min_latency: int = 1, max_latency: int = 200) -> Dict[str, Tuple[int, float]]:
        results = {}
        
        async def scan_one(ip: str):
            best_port, best_latency = await self.scan_ip_parallel(ip, ports, timeout, min_latency, max_latency)
            if best_latency is not None:
                results[ip] = (best_port, best_latency)
        
        chunk_size = 100
        for i in range(0, len(ips), chunk_size):
            chunk = ips[i:i+chunk_size]
            tasks = [scan_one(ip) for ip in chunk]
            await asyncio.gather(*tasks, return_exceptions=True)
        
        return results

class AsyncStorage:
    def __init__(self, path: str):
        self.path = path
        self.pool = None
        self._lock = asyncio.Lock()
        self.batch_buffer = []
        self.buffer_lock = asyncio.Lock()
        self.buffer_size = 2000

    async def init(self):
        self.pool = await aiosqlite.connect(self.path)
        await self.pool.execute("PRAGMA journal_mode=WAL")
        await self.pool.execute("PRAGMA synchronous=NORMAL")
        await self.pool.execute("""
            CREATE TABLE IF NOT EXISTS proxies (
                ip TEXT PRIMARY KEY,
                port INTEGER,
                avg_latency REAL,
                last_seen REAL,
                country TEXT,
                created_at REAL,
                http_working BOOLEAN DEFAULT 0
            )
        """)
        await self.pool.commit()

    async def insert_batch(self, proxies: List[Dict]):
        if not proxies:
            return
        async with self._lock:
            await self.pool.executemany("""
                INSERT OR REPLACE INTO proxies (ip, port, avg_latency, last_seen, country, created_at, http_working)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, [(p["ip"], p["port"], p["avg_latency"], p["last_seen"],
                  p.get("country", "XX"), p.get("created_at", time.time()), 0) for p in proxies])
            await self.pool.commit()

    async def insert_fast(self, proxy: Dict):
        should_flush = False
        buffer_copy = None
        async with self.buffer_lock:
            self.batch_buffer.append(proxy)
            if len(self.batch_buffer) >= self.buffer_size:
                buffer_copy = self.batch_buffer.copy()
                self.batch_buffer.clear()
                should_flush = True
        if should_flush and buffer_copy:
            await self.insert_batch(buffer_copy)

    async def flush(self):
        should_flush = False
        buffer_copy = None
        async with self.buffer_lock:
            if self.batch_buffer:
                buffer_copy = self.batch_buffer.copy()
                self.batch_buffer.clear()
                should_flush = True
        if should_flush and buffer_copy:
            await self.insert_batch(buffer_copy)

    async def get_best(self, limit: int = 4000) -> List[Dict]:
        async with self.pool.execute("""
            SELECT ip, port, avg_latency, country, http_working FROM proxies
            WHERE avg_latency > 0
            ORDER BY avg_latency ASC
            LIMIT ?
        """, (limit,)) as cursor:
            rows = await cursor.fetchall()
            return [{"ip": r[0], "port": r[1], "avg_latency": r[2], "country": r[3], "http_working": bool(r[4])}
                    for r in rows]

    async def get_count(self) -> int:
        async with self.pool.execute("SELECT COUNT(*) FROM proxies") as cursor:
            row = await cursor.fetchone()
            return row[0] if row else 0

    async def close(self):
        if self.pool:
            await self.pool.close()

class FastGeoEnricher:
    def __init__(self, mmdb_path: str = None, thread_pool: int = 2):
        self.mmdb = None
        self.cache = {}
        if mmdb_path and os.path.exists(mmdb_path) and HAS_MAXMIND:
            try:
                self.mmdb = maxminddb.open(mmdb_path)
            except:
                pass
    
    async def get_country_batch(self, ips: List[str]) -> Dict[str, str]:
        results = {}
        uncached = []
        for ip in ips:
            if ip in self.cache:
                results[ip] = self.cache[ip]
            else:
                uncached.append(ip)
        if not uncached:
            return results
        if self.mmdb:
            for ip in uncached:
                try:
                    data = self.mmdb.get(ip)
                    if data and "country" in data:
                        results[ip] = data["country"]["iso_code"]
                        self.cache[ip] = results[ip]
                    else:
                        results[ip] = "XX"
                        self.cache[ip] = "XX"
                except:
                    results[ip] = "XX"
                    self.cache[ip] = "XX"
        for ip in uncached:
            if ip not in results:
                results[ip] = "XX"
                self.cache[ip] = "XX"
        return results
    
    async def close(self):
        if self.mmdb:
            self.mmdb.close()

class LocalQueue:
    def __init__(self, maxsize: int = 50000):
        self.queue = asyncio.Queue(maxsize=maxsize)
    
    async def push_event(self, event: Dict[str, Any]):
        try:
            await self.queue.put(event)
        except:
            pass
    
    async def pull_events(self, count: int = 500) -> List[Dict]:
        events = []
        for _ in range(count):
            try:
                event = await asyncio.wait_for(self.queue.get(), timeout=0.01)
                events.append(event)
            except:
                break
        return events
    
    async def get_queue_size(self) -> int:
        return self.queue.qsize()

class ProgressTracker:
    def __init__(self, total: int = 0, interval: int = 5):
        self.total = total
        self.current = 0
        self.interval = interval
        self.start_time = time.time()
        self.last_update = time.time()
        self.stage = "TCP"
    
    def update(self, count: int = 1, stage: str = None):
        self.current += count
        if stage:
            self.stage = stage
        now = time.time()
        if self.total > 0 and now - self.last_update >= self.interval:
            elapsed = now - self.start_time
            rate = self.current / elapsed if elapsed > 0 else 0
            remaining = (self.total - self.current) / rate if rate > 0 else 0
            logging.info(f"[{self.stage}] {self.current}/{self.total} ({self.current/self.total*100:.1f}%) Rate: {rate:.1f}/s ETA: {remaining:.0f}s")
            self.last_update = now
    
    def finish(self):
        elapsed = time.time() - self.start_time
        if self.current > 0:
            logging.info(f"Completed: {self.current} items in {elapsed:.1f}s ({self.current/elapsed:.1f}/s)")
    
    def set_total(self, total: int):
        self.total = total

class SharedResources:
    def __init__(self, config: Config):
        self.config = config
        self.queue = LocalQueue()
        self.storage = AsyncStorage(config.db_path)
        self.geo = FastGeoEnricher(config.maxmind_path, config.geo_thread_pool)
        self._initialized = False
    
    async def init(self):
        if not self._initialized:
            await self.storage.init()
            self._initialized = True

class HybridWorker:
    def __init__(self, config: Config, worker_id: int, shared: SharedResources, progress: ProgressTracker = None):
        self.config = config
        self.worker_id = worker_id
        self.shared = shared
        self.progress = progress
        self.logger = logging.getLogger(f"Worker-{worker_id}")
        self.scanner = FastTCPScanner(max_concurrent=200)
        self.running = True
        self.stats = {"scanned": 0, "accepted": 0}

    def stop(self):
        self.running = False

    async def scan_batch(self, ips: List[str]) -> List[Dict]:
        if not ips:
            return []
        results = []
        tcp_results = await self.scanner.scan_batch(
            ips, self.config.ports, self.config.tcp_timeout, self.config.min_latency, self.config.quality_threshold
        )
        if tcp_results:
            ip_list = list(tcp_results.keys())
            countries = await self.shared.geo.get_country_batch(ip_list)
            for ip, (port, latency) in tcp_results.items():
                proxy_data = {
                    "ip": ip, "port": port, "avg_latency": latency,
                    "last_seen": time.time(), "country": countries.get(ip, "XX"),
                    "created_at": time.time(), "http_working": False
                }
                results.append(proxy_data)
                self.stats["accepted"] += 1
                await self.shared.storage.insert_fast(proxy_data)
        self.stats["scanned"] += len(ips)
        if self.progress:
            self.progress.update(len(ips))
        return results

    async def consume_loop(self):
        self.logger.info(f"Worker {self.worker_id} started")
        while self.running:
            try:
                events = await self.shared.queue.pull_events(count=200)
                if not events:
                    await asyncio.sleep(0.01)
                    continue
                batch_ips = [e["ip"] for e in events if "ip" in e]
                if batch_ips:
                    await self.scan_batch(batch_ips)
            except:
                await asyncio.sleep(0.1)
        await self.shared.storage.flush()

class HybridPipeline:
    def __init__(self, config: Config = None):
        self.config = config or Config()
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
        self.logger = logging.getLogger("HybridPipeline")
        self.shared = SharedResources(self.config)
        self.progress = ProgressTracker(interval=5)
        self.workers = []
        self.num_workers = min(self.config.max_workers, multiprocessing.cpu_count())
        self.executor = ThreadPoolExecutor(max_workers=4)

    async def fetch_and_push_ips(self):
        self.logger.info("Fetching IPs...")
        sources = [
            "https://raw.githubusercontent.com/123jjck/cdn-ip-ranges/main/cloudflare/cloudflare_plain_ipv4.txt",
            "https://raw.githubusercontent.com/123jjck/cdn-ip-ranges/main/fastly/fastly_plain_ipv4.txt",
            "https://raw.githubusercontent.com/123jjck/cdn-ip-ranges/main/akamai/akamai_plain_ipv4.txt"
        ]
        total_ips = 0
        async with aiohttp.ClientSession() as session:
            for url in sources:
                if total_ips >= 5000:
                    break
                try:
                    async with session.get(url, timeout=10) as resp:
                        if resp.status != 200:
                            continue
                        text = await resp.text()
                        def parse_ips(text: str) -> List[str]:
                            ips = []
                            seen = set()
                            for line in text.splitlines():
                                if "/" in line:
                                    try:
                                        net = ipaddress.ip_network(line.strip(), strict=False)
                                        if net.num_addresses > 2:
                                            sample = min(50, max(5, int(net.num_addresses / 1000)))
                                            for _ in range(sample):
                                                offset = random.randint(1, net.num_addresses - 2)
                                                ip_str = str(net.network_address + offset)
                                                if ip_str not in seen:
                                                    seen.add(ip_str)
                                                    ips.append(ip_str)
                                    except:
                                        pass
                            return ips
                        loop = asyncio.get_event_loop()
                        ips = await loop.run_in_executor(self.executor, parse_ips, text)
                        self.logger.info(f"Got {len(ips)} IPs from {url}")
                        for ip in ips[:500]:
                            await self.shared.queue.push_event({"ts": time.time(), "ip": ip})
                            total_ips += 1
                except:
                    pass
        self.progress.set_total(total_ips)
        self.logger.info(f"All {total_ips} IPs pushed")

    async def run(self):
        self.logger.info("Starting Ultra-Fast Scanner...")
        self.logger.info(f"Workers: {self.num_workers}, Timeout: {self.config.tcp_timeout}s, Ports: {self.config.ports}")
        await self.shared.init()
        for i in range(self.num_workers):
            worker = HybridWorker(self.config, i, self.shared, self.progress)
            self.workers.append(worker)
        producer = asyncio.create_task(self.fetch_and_push_ips())
        workers = [asyncio.create_task(w.consume_loop()) for w in self.workers]
        try:
            await producer
            self.logger.info("Waiting for queue to drain...")
            for _ in range(20):
                qsize = await self.shared.queue.get_queue_size()
                if qsize == 0:
                    break
                await asyncio.sleep(1)
            for w in self.workers:
                w.stop()
            await asyncio.sleep(1)
            await asyncio.gather(*workers, return_exceptions=True)
            self.progress.finish()
            best = await self.shared.storage.get_best(self.config.max_output_ips)
            self.logger.info(f"Found {len(best)} proxies")
            with open("proxies_output.txt", "w") as f:
                f.write("IP,Port,Latency(ms),Country\n")
                for p in best:
                    f.write(f"{p['ip']},{p['port']},{p['avg_latency']:.0f},{p['country']}\n")
            with open("proxies_output.json", "w") as f:
                json.dump(best, f, indent=2)
        finally:
            await self.shared.storage.close()
            await self.shared.geo.close()
            self.executor.shutdown(wait=False)

async def main():
    config = Config(
        max_workers=4,
        batch_size=500,
        tcp_timeout=0.3,
        max_output_ips=4000,
        maxmind_path="GeoLite2-Country.mmdb",
        enable_prometheus=False
    )
    pipeline = HybridPipeline(config)
    await pipeline.run()

if __name__ == "__main__":
    asyncio.run(main())
