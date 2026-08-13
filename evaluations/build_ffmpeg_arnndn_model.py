"""Build a minimal arnndn model with an oversized denoise output layer."""

from __future__ import annotations

import argparse
from pathlib import Path


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    parser.add_argument("--denoise-outputs", type=int, default=23)
    return parser.parse_args()


def _line(values: list[int]) -> str:
    return " ".join(map(str, values))


def _dense(nb_inputs: int, nb_neurons: int) -> list[str]:
    return [
        _line([nb_inputs, nb_neurons, 0]),
        _line([0] * (nb_inputs * nb_neurons)),
        _line([0] * nb_neurons),
    ]


def _gru(nb_inputs: int, nb_neurons: int) -> list[str]:
    return [
        _line([nb_inputs, nb_neurons, 0]),
        _line([0] * (nb_inputs * nb_neurons * 3)),
        _line([0] * (nb_neurons * nb_neurons * 3)),
        _line([0] * (nb_neurons * 3)),
    ]


def build_model(output: Path, denoise_outputs: int) -> None:
    """Write a syntactically valid minimal model with the requested output size."""

    if not 1 <= denoise_outputs <= 128:
        raise ValueError("denoise output count must be in [1, 128]")

    lines = ["rnnoise-nu model file version 1"]
    lines.extend(_dense(42, 1))
    lines.extend(_gru(1, 1))
    lines.extend(_gru(44, 1))
    lines.extend(_gru(44, 1))
    lines.extend(_dense(1, denoise_outputs))
    lines.extend(_dense(1, 1))
    output.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    args = _arguments()
    build_model(args.output, args.denoise_outputs)


if __name__ == "__main__":
    main()
