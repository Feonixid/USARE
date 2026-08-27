import os
import importlib.util
import logging
from typing import List, Any, Dict
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger("usare.plugin_loader")

class NSERunner:
    """
    Dynamically loads and optionally runs Nmap-Scripting-Engine-like Python plugins
    from a specified scripts/ directory dropping into the post-scan execution.
    """
    def __init__(self, scripts_dir: str = "", max_workers: int = 10):
        # Default to <USARE_ROOT>/scripts/ so plugins are always found regardless of CWD
        if not scripts_dir:
            scripts_dir = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"
            )
        self.scripts_dir = scripts_dir
        self.plugins: Dict[str, Any] = {}
        self.max_workers = max_workers
        self._load_plugins()

    def _load_plugins(self):
        if not os.path.exists(self.scripts_dir):
            try:
                os.makedirs(self.scripts_dir)
                logger.info(f"Created plugin directory: {self.scripts_dir}")
            except Exception as e:
                logger.error(f"Could not create scripts directory: {e}")
                return

        for filename in os.listdir(self.scripts_dir):
            if filename.endswith(".py") and not filename.startswith("__"):
                plugin_name = filename[:-3]  # type: ignore[index]
                file_path = os.path.join(self.scripts_dir, filename)
                try:
                    spec = importlib.util.spec_from_file_location(plugin_name, file_path)
                    if spec and spec.loader:
                        module = importlib.util.module_from_spec(spec)
                        if getattr(spec.loader, "exec_module", None) is not None:
                            spec.loader.exec_module(module)  # type: ignore[attr-defined]
                        
                        # Validate that it has a run() method
                        if hasattr(module, 'run') and callable(getattr(module, 'run')):
                            self.plugins[plugin_name] = module
                            logger.debug(f"Loaded USARE script plugin: {plugin_name}")
                        else:
                            logger.warning(f"Plugin {plugin_name} is missing a callable run() function.")
                except Exception as e:
                    logger.error(f"Failed to load plugin {plugin_name}: {e}")
                    
        logger.info(f"Successfully loaded {len(self.plugins)} script plugins.")

    def execute_all(self, target_ip: str, port_data: List[dict],
                    script_args: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Executes all loaded plugins against the target leveraging a ThreadPool.
        script_args is forwarded to plugins that accept a third argument.
        """
        if not self.plugins:
            return {}

        results = {}
        _script_args = script_args or {}

        def run_plugin(name, module):
            try:
                import inspect
                sig = inspect.signature(module.run)
                if len(sig.parameters) >= 3:
                    # Plugin supports script_args
                    res = module.run(target_ip, port_data, _script_args)
                else:
                    # Legacy plugin — only target + port_data
                    res = module.run(target_ip, port_data)
                return name, res
            except Exception as e:
                logger.error(f"Plugin {name} crashed during execution: {e}")
                return name, {"error": str(e)}

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = [
                executor.submit(run_plugin, name, mod)  # type: ignore[arg-type]
                for name, mod in self.plugins.items()
            ]
            
            for future in futures:
                name, output = future.result()
                if output:
                    results[name] = output

        return results
