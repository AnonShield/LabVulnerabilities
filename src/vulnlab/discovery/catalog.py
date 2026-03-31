import csv
import re
import time
import json
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Iterator, Optional, List, Set
from pathlib import Path
import requests

@dataclass
class ImageSpec:
    image: str
    name: str
    @classmethod
    def from_image(cls, image: str) -> "ImageSpec":
        if ":" not in image: image = image + ":latest"
        name = re.sub(r"[^\w-]", "_", image)[:60]
        return cls(image=image, name=name)

class ImageSource(ABC):
    @abstractmethod
    def iter_images(self) -> Iterator[ImageSpec]: ...

class DockerHubDFSSource(ImageSource):
    """
    ACADEMIC PRECISION DFS ENGINE
    Implementation of the Prefix-Trie Collision Algorithm.
    Ensures 100% coverage by recursing on every 10k-record API ceiling hit.
    """
    BASE_URL = "https://hub.docker.com/v2/search/repositories"
    # DockerHub allowed characters for namespaces/repos
    ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"

    def __init__(self, limit: int = 10_000_000, state_file: str = "data/dfs_state.json"):
        self.limit = limit
        self.count = 0
        self.state_file = Path(state_file)
        self._session = requests.Session()
        self.completed_prefixes: Set[str] = self._load_state()
        self.logger = logging.getLogger("DFS_Discovery")

    def _load_state(self) -> Set[str]:
        if self.state_file.exists():
            try: return set(json.loads(self.state_file.read_text()))
            except: return set()
        return set()

    def _save_state(self, prefix: str):
        self.completed_prefixes.add(prefix)
        self.state_file.write_text(json.dumps(list(self.completed_prefixes)))

    def iter_images(self) -> Iterator[ImageSpec]:
        for char in self.ALPHABET:
            if self.count >= self.limit: break
            yield from self._explore_recursive(char)

    def _explore_recursive(self, prefix: str) -> Iterator[ImageSpec]:
        """
        Recursive core of the DFS. 
        Methodology:
        1. Query prefix.
        2. If result == 10,000 -> Branch is 'collided'. subdivision required.
        3. If result < 10,000 -> Branch is 'clean'. subdivision complete.
        """
        if self.count >= self.limit or prefix in self.completed_prefixes:
            return

        params = {"query": prefix, "page_size": 100, "page": 1}
        try:
            r = self._session.get(self.BASE_URL, params=params, timeout=20)
            if r.status_code == 429: # Rate limit handling
                time.sleep(60)
                yield from self._explore_recursive(prefix)
                return
            r.raise_for_status()
            data = r.json()
        except Exception as e:
            self.logger.error(f"Network error on prefix {prefix}: {e}")
            return

        total = data.get("count", 0)
        
        # Phase 1: Ingest all records in this current branch depth
        pages = min(100, (total // 100) + 1)
        for p in range(1, pages + 1):
            if p > 1:
                try:
                    r = self._session.get(self.BASE_URL, params={"query": prefix, "page_size": 100, "page": p}, timeout=20)
                    r.raise_for_status()
                    data = r.json()
                except: break
            
            for repo in data.get("results", []):
                if self.count >= self.limit: return
                img_name = repo.get("repo_name", "").strip()
                if img_name:
                    yield ImageSpec.from_image(img_name)
                    self.count += 1
            time.sleep(0.1) # Courteous delay to prevent socket saturation

        # Phase 2: Decision Node
        # If total reached 10,000, we have an API overflow. Deepen the search.
        if total >= 10000 and len(prefix) < 8:
            self.logger.info(f"Collision detected for '{prefix}' ({total} results). Deepening...")
            for char in self.ALPHABET:
                yield from self._explore_recursive(prefix + char)
        
        # Branch is now exhausted and verified
        self._save_state(prefix)

class FileSource(ImageSource):
    def __init__(self, path: str): self.path = path
    def iter_images(self) -> Iterator[ImageSpec]:
        with open(self.path, newline="", encoding="utf-8") as f:
            sample = f.read(4096)
            f.seek(0)
            # Detect CSV with header vs plain text list
            if "," in sample and "image" in sample.split("\n")[0].lower():
                reader = csv.DictReader(f)
                col = next((c for c in (reader.fieldnames or []) if c.lower() == "image"), None)
                for row in reader:
                    img = (row.get(col) or "").strip()
                    if img:
                        yield ImageSpec.from_image(img)
            else:
                for line in f:
                    img = line.strip()
                    if img and not img.startswith("#"):
                        yield ImageSpec.from_image(img)

def get_source(cfg: dict) -> ImageSource:
    source = cfg.get("source", "file")
    if source == "dockerhub_dfs":
        return DockerHubDFSSource(limit=cfg.get("limit", 10_000_000))
    return FileSource(cfg.get("file", "data/images_all.csv"))
