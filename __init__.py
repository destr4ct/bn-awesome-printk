from binaryninja import *
from .printk import api


PluginCommand.register("d4printk", "Patch all printk calls", api.patch_printk)