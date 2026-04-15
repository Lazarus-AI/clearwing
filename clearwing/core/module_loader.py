import importlib
import importlib.util
from dataclasses import dataclass
from pathlib import Path


@dataclass
class ModuleInfo:
    """Information about a loaded module."""

    name: str
    path: str
    module_class: type
    description: str = ""
    version: str = "1.0.0"


class ModuleLoader:
    """Dynamic module loader for scanners and exploiters."""

    def __init__(self, module_dirs: list[str] | None = None):
        self.module_dirs = module_dirs or []
        self.loaded_modules: dict[str, ModuleInfo] = {}

    def add_module_dir(self, directory: str) -> None:
        """Add a directory to the module search path."""
        path = Path(directory)
        if path.is_dir() and str(path) not in self.module_dirs:
            self.module_dirs.append(str(path))

    def load_module(self, module_path: str, base_class: type | None = None) -> ModuleInfo:
        """Load a module from a file path."""
        path = Path(module_path)
        if not path.exists():
            raise FileNotFoundError(f"Module file not found: {module_path}")

        module_name = path.stem
        spec = importlib.util.spec_from_file_location(module_name, module_path)
        if spec is None or spec.loader is None:
            raise ImportError(f"Cannot load module: {module_path}")

        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        # Find the main class in the module
        module_class = None
        for name in dir(module):
            obj = getattr(module, name)
            if isinstance(obj, type) and obj != base_class:
                if base_class is None or (isinstance(obj, type) and issubclass(obj, base_class)):
                    module_class = obj
                    break

        if module_class is None:
            raise ImportError(f"No suitable class found in module: {module_path}")

        module_info = ModuleInfo(
            name=module_name,
            path=str(path),
            module_class=module_class,
            description=getattr(module, "DESCRIPTION", ""),
            version=getattr(module, "VERSION", "1.0.0"),
        )

        self.loaded_modules[module_name] = module_info
        return module_info

    def unload_module(self, module_name: str) -> None:
        """Unload a module by name."""
        if module_name in self.loaded_modules:
            del self.loaded_modules[module_name]

    def get_module(self, module_name: str) -> type:
        """Get a loaded module class by name."""
        if module_name not in self.loaded_modules:
            raise KeyError(f"Module not loaded: {module_name}")
        return self.loaded_modules[module_name].module_class

    def list_modules(self) -> list[str]:
        """List all loaded module names."""
        return list(self.loaded_modules.keys())

    def discover_modules(self, pattern: str = "*.py") -> list[str]:
        """Discover modules in the module directories."""
        discovered = []
        for module_dir in self.module_dirs:
            path = Path(module_dir)
            for file_path in path.glob(pattern):
                if file_path.name.startswith("_"):
                    continue
                discovered.append(str(file_path))
        return discovered
