"""Normalizer registry — dynamic discovery and loading of language-specific AST normalizers.

Each language subpackage calls ``register()`` in its ``__init__.py``.
The ``get_normalizer()`` function lazily imports the matching subpackage
on first call, so adding a new language requires zero changes to core code.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.graph.node_edge_schema import UnifiedNode, UnifiedEdge

__all__ = ["register", "get_normalizer", "list_languages"]


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

_registry: dict[str, str] = {}
"""Mapping of language name → fully-qualified module path.

Example::

    {
        'php': 'core.graph.normalizers.php.normalizer',
        'javascript': 'core.graph.normalizers.javascript.normalizer',
        ...
    }
"""


def register(language: str, module_path: str | None = None) -> None:
    """Register a normalizer for *language*.

    Can be used as a simple call or a decorator::

        # Simple call
        register('php', 'core.graph.normalizers.php.normalizer')

        # Module path is auto-derived from language name if omitted
        register('php')  # → core.graph.normalizers.php.normalizer

    This is typically called from each language subpackage's ``__init__.py``.
    """
    if module_path is None:
        module_path = f"core.graph.normalizers.{language}.normalizer"
    _registry[language.lower()] = module_path


def get_normalizer(language: str) -> type:
    """Get the Normalizer class for *language*, lazily importing if needed.

    Args:
        language: Language identifier (php, javascript, java, python, go, c).

    Returns:
        The Normalizer class (not an instance).

    Raises:
        KeyError: If no normalizer is registered for this language.
        ImportError: If the module fails to import.
    """
    language = language.lower()
    module_path = _registry.get(language)
    if module_path is None:
        available = ", ".join(sorted(_registry.keys()))
        raise KeyError(
            f"No normalizer registered for '{language}'. "
            f"Available: {available}"
        )
    import importlib
    mod = importlib.import_module(module_path)
    # The module should expose a `Normalizer` class
    if not hasattr(mod, "Normalizer"):
        raise ImportError(
            f"Module {module_path} does not define a 'Normalizer' class"
        )
    return mod.Normalizer


def list_languages() -> list[str]:
    """Return sorted list of registered language names."""
    return sorted(_registry.keys())


# ---------------------------------------------------------------------------
# Pre-register known languages (actual import is lazy via get_normalizer)
# ---------------------------------------------------------------------------

for _lang in ("php", "javascript", "typescript", "python", "java", "go", "c", "cpp", "rust", "ruby", "csharp", "kotlin", "lua"):
    register(_lang)
