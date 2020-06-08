from collections import defaultdict
from graphviz import Digraph
from zelos import CommandLineOption, IPlugin, Zelos
from zelos.exceptions import MemoryReadUnmapped

CommandLineOption(
    "cfg", action="store_true", help="Generate a Control Flow Graph (CFG)."
)

class GraphvizCFG(IPlugin):
    """
    Plugin for zelos that generates a control flow graph using graphviz.
    """
    def __init__(self, z: Zelos):
        super().__init__(z)

        self.logger = self.zelos.logger

        if not self._check_config():
            return

        self.last_inst = None
        self.edges = defaultdict(list)

        if self.zelos.config.cfg:
            self.cfg = Digraph(filename="cfg", format="png")
            self._subscribe_to_feed()

            def closure():
                self.cfg.render()
                self.logger.info("Saved CFG to 'cfg.png'")

            self.zelos.hook_close(closure)

    def _check_config(self):
        """
        Returns True if config settings are appropriately set for this plugin,
        otherwise returns False. The config is acceptable if verbose mode has 
        been specified and the architecture of the target binary is one of
        x86, x86_64, or arm. 
        """
        ret = True
        if (
            self.zelos.config.cfg
            and self.zelos.config.inst_feed == []
            and not self.zelos.config.inst
        ):
            self.logger.error(
                f"You will not be able to generate a CFG if you are not "
                f"running in verbose mode. Include the flag --inst "
                f"(and optionally --fasttrace) to enable verbose mode."
            )
            ret = False
        if (
            self.zelos.config.cfg
            and self.state.arch not in ["x86", "x86_64", "arm"]
        ):
            self.logger.error(
                f"This plugin only supports target architectures x86, x86_64, "
                f"and arm."
            )
            ret = False
        return ret

    @property
    def cs(self):
        return self.zelos.internal_engine.cs

    def _subscribe_to_feed(self):
        feeds = self.zelos.internal_engine.feeds
        feeds.subscribe_to_inst_feed(self._handle_inst)
        feeds.subscribe_to_syscall_feed(self._handle_syscall)

    def _handle_inst(self, zelos, addr=None, size=20):
        if addr is None:
            addr = self.zelos.regs.getIP()
        try:
            code = self.zelos.memory.read(addr, size)
            insts = [x for x in self.cs.disasm(code, addr)]
            self._add_inst_nodes(insts)
        except MemoryReadUnmapped:
            # Can't read this address
            pass

    def _handle_syscall(self, zelos, syscall, args, retval):
        if self.last_inst:
            name = f"{self.last_inst}_{syscall}"
            self.cfg.node(name, f"{syscall}", style="filled", color="#FFCCCC")
            self._create_edge(self.last_inst, name)
            self.last_inst = name

    def _add_inst_nodes(self, insts):
        if len(insts) == 0:
            return
        for inst in insts:
            addr = f"{inst.address:x}"
            self._create_node(inst)
            if self.last_inst:
                self._create_edge(self.last_inst, addr)

            self.last_inst = addr

    def _create_node(self, inst):
        addr = f"{inst.address:x}"
        label = f"{inst.mnemonic} {inst.op_str}"
        if self.state.arch in ["x86", "x86_64"]:
            if inst.mnemonic[0] == "j" or inst.mnemonic == "loop":
                self.cfg.node(addr, label, style="filled", color="#CCCCFF")
                return
            elif inst.mnemonic == "call":
                self.cfg.node(addr, label, style="filled", color="#CCFFCC")
                return
        elif self.state.arch in ["arm"]:
            if inst.mnemonic[0] == "b" and inst.mnemonic not in ["bic", "bkpt"]:
                self.cfg.node(addr, label, style="filled", color="#CCCCFF")
                return
        self.cfg.node(addr, label)

    def _create_edge(self, a, b):
        if b in self.edges[a]:
            return
        self.cfg.edge(a, b)
        self.edges[a].append(b)
