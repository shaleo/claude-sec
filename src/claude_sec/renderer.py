from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from claude_sec.models import ScanResult

TEMPLATE_DIR = Path(__file__).parent / "templates"


def render_html(result: ScanResult) -> str:
    env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)), autoescape=True)
    template = env.get_template("report.html")
    return template.render(result=result)
