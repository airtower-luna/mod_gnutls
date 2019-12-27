"""Test case hooks for mod_gnutls tests

Test cases can implement hooks that (depending on the hook) override
or supplement the default test run behavior."""

import importlib.util
import inspect
import os.path

hooks = [
    'prepare_env',
    'run_connection',
    'post_check'
]

class Plugin:
    def __init__(self, module=None):
        self.module = module
        for hook in hooks:
            if module:
                func = getattr(module, hook, None)
                if func and not inspect.isfunction(func):
                    raise TypeError(f'{hook} in plugin module must be '
                                    'a function!')
                setattr(self, hook, func)
            else:
                setattr(self, hook, None)

def load_module_file(file_path, module_name='mgstest.plugin'):
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def load_hooks_plugin(file_path, module_name='mgstest.plugin'):
    """Load a hooks plugin module from the given path, if it
    exists. Returns a Plugin instance without any hooks if the module
    file does not exist.
    """
    if os.path.exists(file_path):
        return Plugin(module=load_module_file(file_path, module_name))
    else:
        return Plugin()
