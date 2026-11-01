"""Builds documents for the demo app from a short spec: visible text, optional hidden text and
how to hide it, and optional metadata. The red-team harness plants these per attack.
"""

from __future__ import annotations

import html
import io
import textwrap
from typing import Literal

from pydantic import BaseModel, Field

DocumentFormat = Literal["html", "markdown", "text", "pdf", "docx"]
# Per format, the hiding methods it supports. The first one is the default.
HIDING_METHODS: dict[str, tuple[str, ...]] = {
    "html": (
        "display_none",
        "visibility_hidden",
        "font_size_zero",
        "white_text",
        "offscreen",
        "comment",
    ),
    "markdown": ("comment",),
    "text": ("plain",),
    "pdf": ("white", "tiny", "offpage"),
    "docx": ("vanish", "white"),
}
_HTML_HIDING = {
    "display_none": '<div style="display:none">{}</div>',
    "visibility_hidden": '<p style="visibility:hidden">{}</p>',
    "font_size_zero": '<span style="font-size:0">{}</span>',
    "white_text": '<p style="color:#ffffff;background:#ffffff">{}</p>',
    "offscreen": '<div style="position:absolute;left:-9999px">{}</div>',
    "comment": "<!-- {} -->",
}
METADATA_FIELDS = ("title", "subject", "keywords", "author")


class DocumentSpec(BaseModel):
    name: str = Field(min_length=1, max_length=128, pattern=r"^[\w.-]+$")
    format: DocumentFormat
    content: str = Field(max_length=50_000)
    hidden: str | None = Field(default=None, max_length=10_000)
    hiding: str | None = None
    metadata: dict[str, str] = Field(default_factory=dict)

    def hiding_method(self) -> str:
        methods = HIDING_METHODS[self.format]
        method = self.hiding or methods[0]
        if method not in methods:
            raise ValueError(f"{self.format} documents support hiding {', '.join(methods)}")
        return method

    @property
    def suffix(self) -> str:
        return {"html": ".html", "markdown": ".md", "text": ".txt"}.get(
            self.format, f".{self.format}"
        )


def render(spec: DocumentSpec) -> bytes:
    if set(spec.metadata) - set(METADATA_FIELDS):
        raise ValueError(f"metadata fields: {', '.join(METADATA_FIELDS)}")
    method = spec.hiding_method()
    if spec.format == "pdf":
        return _pdf(spec, method)
    if spec.format == "docx":
        return _docx(spec, method)
    if spec.format == "html":
        hidden = _HTML_HIDING[method].format(html.escape(spec.hidden)) if spec.hidden else ""
        title = html.escape(spec.metadata.get("title", spec.name))
        meta = "".join(
            f'<meta name="{k}" content="{html.escape(v)}">'
            for k, v in spec.metadata.items()
            if k != "title"
        )
        page = f"<html><head><title>{title}</title>{meta}</head><body>{spec.content}{hidden}"
        return f"{page}</body></html>".encode()
    text = spec.content
    if spec.hidden:
        text += f"\n\n<!-- {spec.hidden} -->" if method == "comment" else f"\n\n{spec.hidden}"
    return text.encode()


def _pdf(spec: DocumentSpec, method: str) -> bytes:
    from reportlab.pdfgen import canvas

    buffer = io.BytesIO()
    c = canvas.Canvas(buffer)
    c.setTitle(spec.metadata.get("title", spec.name))
    c.setSubject(spec.metadata.get("subject", ""))
    c.setKeywords(spec.metadata.get("keywords", ""))
    c.setAuthor(spec.metadata.get("author", ""))
    c.setFont("Helvetica", 11)
    y = 760.0
    for paragraph in spec.content.split("\n"):
        for line in textwrap.wrap(paragraph, 90) or [""]:
            c.drawString(72, y, line)
            y -= 16
    if spec.hidden:
        size, x = {"white": (11.0, 72.0), "tiny": (1.0, 72.0), "offpage": (11.0, -2000.0)}[method]
        if method == "white":
            c.setFillColorRGB(1, 1, 1)  # invisible on the page, readable by a parser
        c.setFont("Helvetica", size)
        y -= 20
        for line in textwrap.wrap(spec.hidden, 90):
            c.drawString(x, y, line)
            y -= max(size + 2, 6)  # pdfplumber merges lines closer than 3pt
    c.showPage()
    c.save()
    return buffer.getvalue()


def _docx(spec: DocumentSpec, method: str) -> bytes:
    import docx
    from docx.shared import RGBColor

    document = docx.Document()
    for key in METADATA_FIELDS:
        if key in spec.metadata:
            setattr(document.core_properties, key, spec.metadata[key])
    paragraph = None
    for text in spec.content.split("\n"):
        paragraph = document.add_paragraph(text)
    if spec.hidden:
        run = (paragraph or document.add_paragraph()).add_run(" " + spec.hidden)
        if method == "vanish":
            run.font.hidden = True
        run.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
    buffer = io.BytesIO()
    document.save(buffer)
    return buffer.getvalue()
