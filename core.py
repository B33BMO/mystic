import os
import importlib
import threading
import logging

logging.basicConfig(level=logging.INFO)

PLUGINS_DIR = "./plugins"

def load_plugins():
    plugins = []
    for fname in os.listdir(PLUGINS_DIR):
        if fname.endswith(".py") and not fname.startswith("__"):
            module_name = fname[:-3]
            module = importlib.import_module(f"plugins.{module_name}")
            if hasattr(module, "run"):
                plugins.append(module)
                logging.info(f"Loaded plugin: {module_name}")
    return plugins

def main():
    logging.info("Starting CyberGuard...")
    plugins = load_plugins()
    threads = []
    for plugin in plugins:
        t = threading.Thread(target=plugin.run, daemon=True)
        t.start()
        threads.append(t)
    logging.info("All plugins launched. CyberGuard running.")
    for t in threads:
        t.join()

if __name__ == "__main__":
    main()