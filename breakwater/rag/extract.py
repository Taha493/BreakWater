"""Text extraction for the document scanner (spec section 7).

Each extractor returns the text a human reader would see, plus every piece of text they
would not: HTML comments and CSS-hidden elements, tiny, white, or off-page text in PDFs,
hidden, white, or tiny runs in Word files, image alt text, and document metadata. Hidden
pieces are scanned separately and never returned to callers as indexable text.

Limits: only inline styles and simple ``.class``/``#id`` rules in ``<style>`` blocks are
evaluated (no external stylesheets or full CSS cascade), and "white" text assumes a white
background unless an ancestor declares another background colour.
"""

from __future__ import annotations

import io
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from bs4 import BeautifulSoup, Comment, Tag

MAX_PDF_PAGES = 200
TINY_FONT_PT = 2.0
_MARKDOWN_COMMENT = re.compile(r"\[(?://|comment)\]: ?(?:#|<>) ?\(([^()\[\]]{0,4000})\)")
_MARKDOWN_IMAGE = re.compile(r"!\[([^\[\]\n]{1,500})\]\(")


class DocumentFormat(StrEnum):
    TEXT = "text"
    MARKDOWN = "markdown"
    HTML = "html"
    PDF = "pdf"
    DOCX = "docx"


class ExtractionError(ValueError):
    pass


@dataclass(frozen=True)
class HiddenSegment:
    # html_comment, html_css_hidden, html_hidden_attribute, markdown_comment, alt_text,
    # metadata, pdf_tiny_text, pdf_white_text, pdf_offpage_text, docx_hidden_text,
    # docx_white_text, docx_tiny_text
    kind: str
    text: str


@dataclass
class Extracted:
    visible: str
    hidden: list[HiddenSegment] = field(default_factory=list)

    def add(self, kind: str, text: str) -> None:
        text = " ".join(text.split())
        if text:
            self.hidden.append(HiddenSegment(kind, text))


def extract(data: bytes, fmt: DocumentFormat) -> Extracted:
    try:
        if fmt is DocumentFormat.PDF:
            return extract_pdf(data)
        if fmt is DocumentFormat.DOCX:
            return extract_docx(data)
        text = data.decode("utf-8")
    except ExtractionError:
        raise
    except Exception as exc:
        raise ExtractionError(f"could not read {fmt.value} document") from exc
    if fmt is DocumentFormat.HTML:
        return extract_html(text)
    if fmt is DocumentFormat.MARKDOWN:
        return extract_markdown(text)
    return Extracted(visible=text)


# ---- HTML ----------------------------------------------------------------------------

_WHITE = {"white", "#fff", "#ffffff", "#fffffe", "rgb(255,255,255)", "rgba(255,255,255,1)"}
_HIDING_DECLARATIONS = (
    re.compile(r"display\s*:\s*none"),
    re.compile(r"visibility\s*:\s*(?:hidden|collapse)"),
    re.compile(r"opacity\s*:\s*0(?:\.0+)?\s*(?:;|$)"),
    re.compile(r"font-size\s*:\s*(?:0|[01](?:\.\d+)?px|0(?:\.\d+)?(?:em|rem|pt))\s*(?:;|$)"),
    re.compile(r"(?:^|;)\s*(?:width|height)\s*:\s*0(?:px)?\s*(?:;|$)"),
    re.compile(r"(?:left|top|text-indent)\s*:\s*-\d{3,}"),
    re.compile(r"clip\s*:\s*rect\(\s*0"),
)
_BLOCK_TAGS = [
    "p", "div", "section", "article", "header", "footer", "aside", "nav", "main", "li", "ul",
    "ol", "table", "tr", "td", "th", "h1", "h2", "h3", "h4", "h5", "h6", "blockquote", "pre",
    "dt", "dd", "figure", "figcaption", "hr", "form", "title",
]  # fmt: skip
_CSS_RULE = re.compile(r"([.#][\w-]+)\s*\{([^{}]{0,2000})\}")


def _declarations(style: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for part in style.lower().split(";"):
        if ":" in part:
            key, value = part.split(":", 1)
            out[key.strip()] = value.replace(" ", "").strip()
    return out


def _hides(style: str) -> bool:
    style = style.lower()
    return any(p.search(style) for p in _HIDING_DECLARATIONS)


def _background(tag: Tag) -> str:
    node: Tag | None = tag
    while node is not None:
        decls = _declarations(str(node.get("style") or ""))
        for key in ("background-color", "background"):
            if key in decls:
                return decls[key]
        node = node.parent if isinstance(node.parent, Tag) else None
    return "white"


def _color(value: str) -> str:
    return value.replace(" ", "").lower()


def _hidden_selectors(soup: BeautifulSoup) -> set[str]:
    selectors: set[str] = set()
    for style in soup.find_all("style"):
        for selector, body in _CSS_RULE.findall(style.get_text()):
            if _hides(body):
                selectors.add(selector)
    return selectors


def _hidden_reason(tag: Tag, selectors: set[str]) -> str | None:
    if tag.has_attr("hidden"):
        return "html_hidden_attribute"
    style = str(tag.get("style") or "")
    if _hides(style):
        return "html_css_hidden"
    classes: list[str] = list(tag.get("class") or [])
    names = {f".{c}" for c in classes} | ({f"#{tag['id']}"} if tag.has_attr("id") else set())
    if names & selectors:
        return "html_css_hidden"
    color = _declarations(style).get("color")
    if color is not None and _color(color) == _color(_background(tag)):
        return "html_css_hidden"
    if color is not None and _color(color) in _WHITE and _color(_background(tag)) in _WHITE:
        return "html_css_hidden"
    return None


def extract_html(html: str) -> Extracted:
    soup = BeautifulSoup(html, "html.parser")
    result = Extracted(visible="")
    for comment in soup.find_all(string=lambda s: isinstance(s, Comment)):
        result.add("html_comment", str(comment))
        comment.extract()
    selectors = _hidden_selectors(soup)
    for tag in soup.find_all(["script", "style", "template", "noscript"]):
        tag.decompose()
    for meta in soup.find_all("meta"):
        content = meta.get("content")
        if content and (meta.get("name") or meta.get("property")):
            result.add("metadata", str(content))
    for tag in soup.find_all(True):
        if tag.decomposed:  # removed with a hidden ancestor
            continue
        reason = _hidden_reason(tag, selectors)
        if reason is not None:
            result.add(reason, tag.get_text(" "))
            tag.decompose()
    for tag in soup.find_all(["img", "area", "input"]):
        for attr in ("alt", "title"):
            if tag.get(attr):
                result.add("alt_text", str(tag[attr]))
    for tag in soup.find_all("br"):
        tag.replace_with("\n")
    for tag in soup.find_all(_BLOCK_TAGS):
        tag.insert_before("\n")
        tag.insert_after("\n")
    result.visible = _clean_lines(soup.get_text(""))
    return result


def _clean_lines(text: str) -> str:
    lines = [" ".join(line.split()) for line in text.splitlines()]
    out: list[str] = []
    for line in lines:
        if line or (out and out[-1]):
            out.append(line)
    return "\n".join(out).strip()


# ---- Markdown ------------------------------------------------------------------------


def extract_markdown(text: str) -> Extracted:
    hidden: list[HiddenSegment] = []
    for m in _MARKDOWN_COMMENT.finditer(text):
        hidden.append(HiddenSegment("markdown_comment", m.group(1).strip()))
    for m in _MARKDOWN_IMAGE.finditer(text):
        hidden.append(HiddenSegment("alt_text", m.group(1).strip()))
    text = _MARKDOWN_COMMENT.sub("", text)
    # Markdown may embed HTML; run it through the HTML extractor for comments and hiding.
    html = extract_html(text) if "<" in text else Extracted(visible=text)
    return Extracted(visible=html.visible, hidden=[*hidden, *html.hidden])


# ---- PDF -----------------------------------------------------------------------------


def _is_white(color: object) -> bool:
    if not isinstance(color, (tuple, list)) or not color:
        return False
    try:
        values = [float(v) for v in color]
    except (TypeError, ValueError):
        return False
    if len(values) == 4:  # CMYK: white is no ink
        return all(v <= 0.05 for v in values)
    return all(v >= 0.95 for v in values)  # grayscale or RGB


def _pdf_char_kind(char: dict[str, object], width: float, height: float) -> str | None:
    size = char.get("size")
    if isinstance(size, (int, float)) and size < TINY_FONT_PT:
        return "pdf_tiny_text"
    if _is_white(char.get("non_stroking_color")):
        return "pdf_white_text"
    x0, top = char.get("x0"), char.get("top")
    if isinstance(x0, (int, float)) and isinstance(top, (int, float)):
        if x0 < 0 or x0 > width or top < 0 or top > height:
            return "pdf_offpage_text"
    return None


def _visible_char_filter(width: float, height: float) -> Callable[[dict[str, Any]], bool]:
    def keep(obj: dict[str, Any]) -> bool:
        return obj.get("object_type") != "char" or _pdf_char_kind(obj, width, height) is None

    return keep


def extract_pdf(data: bytes) -> Extracted:
    import pdfplumber

    result = Extracted(visible="")
    pages: list[str] = []
    try:
        with pdfplumber.open(io.BytesIO(data)) as pdf:
            if len(pdf.pages) > MAX_PDF_PAGES:
                raise ExtractionError(f"PDF has more than {MAX_PDF_PAGES} pages")
            for key, value in (pdf.metadata or {}).items():
                if key in ("Title", "Subject", "Keywords", "Author", "Creator") and value:
                    result.add("metadata", str(value))
            for page in pdf.pages:
                width, height = float(page.width), float(page.height)
                runs: list[tuple[str, list[str]]] = []
                for char in page.chars:
                    kind = _pdf_char_kind(char, width, height)
                    if kind is None:
                        continue
                    if runs and runs[-1][0] == kind:
                        runs[-1][1].append(str(char.get("text", "")))
                    else:
                        runs.append((kind, [str(char.get("text", ""))]))
                for kind, chars in runs:
                    result.add(kind, "".join(chars))
                visible = page.filter(_visible_char_filter(width, height))
                pages.append(visible.extract_text() or "")
    except ExtractionError:
        raise
    except Exception as exc:
        raise ExtractionError("could not read PDF document") from exc
    result.visible = "\n\n".join(p.strip() for p in pages if p.strip())
    return result


# ---- DOCX ----------------------------------------------------------------------------


def extract_docx(data: bytes) -> Extracted:
    import docx
    from docx.shared import Pt

    try:
        document = docx.Document(io.BytesIO(data))
    except Exception as exc:
        raise ExtractionError("could not read DOCX document") from exc
    result = Extracted(visible="")
    props = document.core_properties
    for value in (props.title, props.subject, props.keywords, props.comments, props.category):
        if value:
            result.add("metadata", str(value))

    paragraphs = list(document.paragraphs)
    for table in document.tables:
        for row in table.rows:
            for cell in row.cells:
                paragraphs.extend(cell.paragraphs)
    for section in document.sections:
        for part in (section.header, section.footer):
            paragraphs.extend(part.paragraphs)

    visible_paragraphs: list[str] = []
    for paragraph in paragraphs:
        visible: list[str] = []
        for run in paragraph.runs:
            font = run.font
            kind = None
            if font.hidden:
                kind = "docx_hidden_text"
            elif (
                font.color is not None
                and font.color.type is not None
                and str(font.color.rgb).upper() in ("FFFFFF", "FFFFFE")
            ):
                kind = "docx_white_text"
            elif font.size is not None and font.size <= Pt(TINY_FONT_PT):
                kind = "docx_tiny_text"
            if kind:
                result.add(kind, run.text)
            else:
                visible.append(run.text)
        line = "".join(visible).strip()
        if line:
            visible_paragraphs.append(line)
    result.visible = "\n\n".join(visible_paragraphs)
    return result
