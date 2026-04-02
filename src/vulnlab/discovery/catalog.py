import csv, re, json, logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Iterator
from pathlib import Path

@dataclass
class ImageSpec:
    image: str; name: str; pull_count: int = 0
    @classmethod
    def from_image(cls, img: str, pc: int = 0):
        if ":" not in img: img += ":latest"
        return cls(img, re.sub(r"[^\w-]", "_", img)[:60], pc)

class ImageSource(ABC):
    @abstractmethod
    def iter_images(self) -> Iterator[ImageSpec]: ...

class DITectorSource(ImageSource):
    """Source from DITector prioritized JSONL output (ImageWeight struct)."""
    def __init__(self, path: str): self.path = Path(path)
    def iter_images(self) -> Iterator[ImageSpec]:
        if not self.path.exists(): return
        with open(self.path, "r") as f:
            for line in f:
                try:
                    data = json.loads(line)
                    # DITector ImageWeight: repository_namespace, repository_name, tag_name, weights
                    ns = data.get("repository_namespace", "")
                    repo = data.get("repository_name", "")
                    tag = data.get("tag_name", "latest")
                    pc = int(data.get("weights") or data.get("pull_count") or 0)
                    if not repo: continue
                    full = f"{ns}/{repo}:{tag}" if ns else f"{repo}:{tag}"
                    yield ImageSpec.from_image(full, pc)
                except: continue

class FileSource(ImageSource):
    def __init__(self, p: str): self.p = p
    def iter_images(self):
        with open(self.p, newline="", encoding="utf-8") as f:
            head = f.readline().lower(); f.seek(0)
            if "," in head and "image" in head:
                r = csv.DictReader(f)
                img_c = next(c for c in (r.fieldnames or []) if c.lower() == "image")
                pc_c = next((c for c in (r.fieldnames or []) if c.lower() == "pull_count"), None)
                for row in r:
                    img = (row.get(img_c) or "").strip()
                    if img: yield ImageSpec.from_image(img, int(row.get(pc_c) or 0) if pc_c else 0)
            else:
                for ln in f:
                    if ln.strip() and not ln.startswith("#"): yield ImageSpec.from_image(ln.strip())

def get_source(cfg: dict):
    if cfg.get("source") == "ditector":
        return DITectorSource(cfg.get("file", "data/ditector_results.jsonl"))
    return FileSource(cfg.get("file", "data/images_all.csv"))
