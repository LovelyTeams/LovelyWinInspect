"""从 assets/logo.(png|jpg|webp) 生成应用图标资源。

用法: python tools/make_icons.py
输出:
  assets/logo_256.png  界面内使用（标题栏等）
  assets/logo_64.png   HTML 报告内嵌
  assets/app.ico       exe / 窗口 / 任务栏图标（16~256 多尺寸）
"""

from pathlib import Path

from PIL import Image

ROOT = Path(__file__).resolve().parent.parent
ASSETS = ROOT / "assets"


def find_source() -> Path:
    for name in ("logo.png", "logo.webp", "logo.jpg", "logo.jpeg"):
        p = ASSETS / name
        if p.exists():
            return p
    raise SystemExit("未找到 assets/logo.png（或 .webp/.jpg）")


def square(img: Image.Image) -> Image.Image:
    w, h = img.size
    side = min(w, h)
    left, top = (w - side) // 2, (h - side) // 2
    return img.crop((left, top, left + side, top + side))


def main() -> None:
    src = find_source()
    img = square(Image.open(src).convert("RGBA"))
    img.resize((256, 256), Image.LANCZOS).save(ASSETS / "logo_256.png", optimize=True)
    img.resize((64, 64), Image.LANCZOS).save(ASSETS / "logo_64.png", optimize=True)
    sizes = [(s, s) for s in (16, 20, 24, 32, 40, 48, 64, 128, 256)]
    img.resize((256, 256), Image.LANCZOS).save(ASSETS / "app.ico", sizes=sizes)
    print(f"已从 {src.name} 生成 logo_256.png / logo_64.png / app.ico")


if __name__ == "__main__":
    main()
