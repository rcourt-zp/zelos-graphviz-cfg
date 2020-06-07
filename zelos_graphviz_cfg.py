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
        self.last_inst = None

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

        if self.zelos.config.cfg:
            self.cfg = Digraph(filename="cfg", format="png")
            self.subscribe_to_feed()

            def closure():
                self.cfg.render()
                self.logger.info("Saved cfg to 'cfg.png'")

            self.zelos.hook_close(closure)

    @property
    def cs(self):
        return self.zelos.internal_engine.cs

    def subscribe_to_feed(self):
        feeds = self.zelos.internal_engine.feeds
        feeds.subscribe_to_inst_feed(self.handle_inst)
        feeds.subscribe_to_syscall_feed(self.handle_syscall)

    def handle_inst(self, zelos, addr=None, size=20):
        if addr is None:
            addr = self.zelos.regs.getIP()
        try:
            code = self.zelos.memory.read(addr, size)
            insts = [x for x in self.cs.disasm(code, addr)]
            self.add_inst_node(insts)
        except MemoryReadUnmapped:
            # Can't read this address
            pass

    def add_inst_node(self, insts):
        if len(insts) == 0:
            return
        for inst in insts:
            addr = f"{inst.address}"
            self.cfg.node(addr, f"{inst.mnemonic} {inst.op_str}")
            if self.last_inst:
                self.cfg.edge(self.last_inst, addr)

            self.last_inst = addr

    def handle_syscall(self, zelos, syscall, args, retval):
        name = f"{self.last_inst}_{syscall}"
        self.cfg.node(name, f"{syscall}", style="filled", color="#FFCCCC")
        self.cfg.edge(self.last_inst, name)
        self.last_inst = name
        