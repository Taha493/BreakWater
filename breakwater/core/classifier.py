"""The injection classifier's model (spec section 6, layer 2), behind a small interface so
the model can be swapped.

``OnnxScorer`` runs a Hugging Face sequence-classification model exported to ONNX with
ONNX Runtime and the ``tokenizers`` library (no torch). Text longer than the model's input
is split into overlapping token windows; each window gets the model's probability for the
injection label. The detector (detectors/injection_classifier.py) takes the maximum.
"""

from __future__ import annotations

import json
import logging
import math
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

import numpy as np

log = logging.getLogger("gateway.classifier")

ONNX_FILE = "model.onnx"
TOKENIZER_FILE = "tokenizer.json"
CONFIG_FILE = "config.json"
MODEL_FILES = (CONFIG_FILE, TOKENIZER_FILE, ONNX_FILE)
DEFAULT_OVERLAP_TOKENS = 64
BATCH_SIZE = 8


@dataclass(frozen=True)
class WindowScore:
    text_index: int  # which of the scored texts
    start: int  # character span of the window in that text
    end: int
    score: float  # probability of the injection label


class InjectionScorer(Protocol):
    """Scores texts for prompt injection. Called from a worker thread."""

    @property
    def model_id(self) -> str:
        """Identifies the model and revision; part of the ruleset version."""
        ...

    def score(self, texts: Sequence[str], max_windows: int) -> list[WindowScore]:
        """Scores for at most ``max_windows`` windows across ``texts``, in order."""
        ...


class ClassifierError(RuntimeError):
    pass


def window_bounds(tokens: int, size: int, overlap: int) -> list[tuple[int, int]]:
    """Token ranges of at most ``size`` covering ``tokens`` tokens, each overlapping the
    previous one by ``overlap`` so an instruction split across a boundary is seen whole."""
    step = max(1, size - overlap)
    bounds: list[tuple[int, int]] = []
    for start in range(0, tokens, step):
        end = min(start + size, tokens)
        bounds.append((start, end))
        if end == tokens:
            break
    return bounds


def pick_windows(count: int, limit: int) -> list[int]:
    """Indexes of the windows to score when there are more than ``limit``: the first and
    last ones, so neither the start nor the end of a long text goes unscanned."""
    if count <= limit:
        return list(range(count))
    head = math.ceil(limit / 2)
    return list(range(head)) + list(range(count - (limit - head), count))


class OnnxScorer:
    def __init__(
        self,
        directory: Path,
        model_id: str,
        injection_label: str = "INJECTION",
        threads: int = 2,
        overlap_tokens: int = DEFAULT_OVERLAP_TOKENS,
    ) -> None:
        import onnxruntime
        from tokenizers import Tokenizer

        config = json.loads((directory / CONFIG_FILE).read_text("utf-8"))
        labels = {str(v): int(k) for k, v in config.get("id2label", {}).items()}
        if injection_label not in labels:
            raise ClassifierError(
                f"label {injection_label!r} not in the model's labels {sorted(labels)}"
            )
        self._label = labels[injection_label]
        self._max_tokens = int(config.get("max_position_embeddings", 512))
        self._tokenizer = Tokenizer.from_file(str(directory / TOKENIZER_FILE))
        self._tokenizer.no_truncation()
        self._tokenizer.no_padding()
        self._cls = self._special("[CLS]", config.get("bos_token_id"))
        self._sep = self._special("[SEP]", config.get("eos_token_id"))
        self._pad = int(config.get("pad_token_id") or 0)
        self._overlap = overlap_tokens
        options = onnxruntime.SessionOptions()
        options.intra_op_num_threads = threads
        options.inter_op_num_threads = 1
        self._session = onnxruntime.InferenceSession(
            str(directory / ONNX_FILE), options, providers=["CPUExecutionProvider"]
        )
        self._inputs = {i.name for i in self._session.get_inputs()}
        if not {"input_ids", "attention_mask"} <= self._inputs:
            raise ClassifierError(f"unexpected model inputs: {sorted(self._inputs)}")
        self._model_id = model_id

    def _special(self, token: str, fallback: Any) -> int:
        found = self._tokenizer.token_to_id(token)
        if found is not None:
            return int(found)
        if fallback is None:
            raise ClassifierError(f"tokenizer has no {token} token")
        return int(fallback)

    @property
    def model_id(self) -> str:
        return self._model_id

    def _windows(self, text_index: int, text: str) -> list[tuple[WindowScore, list[int]]]:
        encoding = self._tokenizer.encode(text, add_special_tokens=False)
        ids, offsets = encoding.ids, encoding.offsets
        # Two positions go to the [CLS] and [SEP] tokens around each window.
        return [
            (
                WindowScore(text_index, offsets[start][0], offsets[end - 1][1], 0.0),
                [self._cls, *ids[start:end], self._sep],
            )
            for start, end in window_bounds(len(ids), self._max_tokens - 2, self._overlap)
        ]

    def score(self, texts: Sequence[str], max_windows: int) -> list[WindowScore]:
        windows = [w for i, text in enumerate(texts) for w in self._windows(i, text)]
        windows = [windows[i] for i in pick_windows(len(windows), max_windows)]
        scored: list[WindowScore] = []
        for first in range(0, len(windows), BATCH_SIZE):
            batch = windows[first : first + BATCH_SIZE]
            probabilities = self._run([ids for _, ids in batch])
            scored += [
                WindowScore(span.text_index, span.start, span.end, float(p))
                for (span, _), p in zip(batch, probabilities, strict=True)
            ]
        return scored

    def _run(self, sequences: list[list[int]]) -> list[float]:
        width = max(len(s) for s in sequences)
        input_ids = np.full((len(sequences), width), self._pad, dtype=np.int64)
        mask = np.zeros((len(sequences), width), dtype=np.int64)
        for row, ids in enumerate(sequences):
            input_ids[row, : len(ids)] = ids
            mask[row, : len(ids)] = 1
        feed = {"input_ids": input_ids, "attention_mask": mask}
        if "token_type_ids" in self._inputs:
            feed["token_type_ids"] = np.zeros_like(input_ids)
        logits = np.asarray(self._session.run(None, feed)[0], dtype=np.float64)
        shifted = np.exp(logits - logits.max(axis=1, keepdims=True))
        probabilities = shifted / shifted.sum(axis=1, keepdims=True)
        return [float(p) for p in probabilities[:, self._label]]


def model_directory(
    model: str, revision: str | None, subfolder: str | None, download: bool = True
) -> Path:
    """A local directory holding the model files: ``model`` itself when it is a directory,
    otherwise the Hugging Face repo ``model`` at ``revision`` (downloaded into the Hugging
    Face cache unless it is there already, or ``download`` is false)."""
    if Path(model).is_dir():
        return Path(model)
    from huggingface_hub import hf_hub_download

    paths = [
        hf_hub_download(
            model,
            name,
            subfolder=subfolder or None,
            revision=revision,
            local_files_only=not download,
        )
        for name in MODEL_FILES
    ]
    return Path(str(paths[0])).parent


def load_scorer(
    model: str,
    revision: str | None,
    subfolder: str | None,
    injection_label: str,
    threads: int,
) -> OnnxScorer:
    """Load the model and run one warm-up inference, so the first real call is not slow."""
    directory = model_directory(model, revision, subfolder)
    model_id = f"{model}@{revision[:12]}" if revision else model
    scorer = OnnxScorer(directory, model_id, injection_label, threads)
    scorer.score(["Warm-up: what are your opening hours?"], 1)
    log.info("classifier loaded", extra={"model": model_id})
    return scorer
