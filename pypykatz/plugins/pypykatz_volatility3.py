import os
import logging
import ntpath
from typing import List

from volatility3.framework import interfaces, renderers, constants
from volatility3.framework.configuration import requirements
from volatility3.plugins.windows import pslist

vollog = logging.getLogger(__name__)

framework_version = constants.VERSION_MAJOR


class pypykatz(interfaces.plugins.PluginInterface):
    _required_framework_version = (framework_version, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        reqs = [
            requirements.StringRequirement(
                name="output",
                description="Save results to file (you can specify --json or --grep, otherwise text format will be written)",
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="json",
                description="Save credentials in JSON format",
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="grep",
                description="Save credentials in greppable format",
                optional=True,
            ),
            requirements.StringRequirement(
                name="kerberos_dir",
                description="Save kerberos tickets to a directory",
                optional=True,
            ),
        ]
        if framework_version == 1:
            kernel_layer_name = "primary"
            reqs += [
                requirements.TranslationLayerRequirement(
                    name=kernel_layer_name,
                    description="Memory layer for the kernel",
                    architectures=["Intel32", "Intel64"],
                ),
                requirements.SymbolTableRequirement(
                    name="nt_symbols", description="Windows kernel symbols"
                ),
                requirements.PluginRequirement(
                    name="pslist", plugin=pslist.PsList, version=(2, 0, 0)
                ),
            ]
        elif framework_version == 2:
            kernel_layer_name = "kernel"
            reqs += [
                requirements.ModuleRequirement(
                    name=kernel_layer_name,
                    description="Windows kernel",
                    architectures=["Intel32", "Intel64"],
                ),
                requirements.VersionRequirement(
                    name="pslist", component=pslist.PsList, version=(3, 0, 0)
                ),
            ]
        else:
            # The highest major version we currently support is 2.
            raise RuntimeError(
                f"Framework interface version {framework_version} is  currently not supported."
            )

        return reqs

    def run(self):
        from pypykatz.pypykatz import pypykatz as pparser
        from pypykatz.commons.readers.volatility3.volreader import vol3_treegrid
        mimi = pparser.go_volatility3(self, framework_version)
        
        out_file = self.config.get("output", None)
        if out_file:
            if self.config.get("json", False):
                output = mimi.to_json()
            elif self.config.get("grep", False):
                output = mimi.to_grep()
            else:
                output = str(mimi)
            with self.open(out_file) as output_data:
                output_data.write(output.encode())

        kerberos_dir = self.config.get("kerberos_dir", None)
        if kerberos_dir:
            directory = os.path.abspath(kerberos_dir)
            if not os.path.isdir(directory):
                os.makedirs(directory)
            base_filename = ntpath.basename('rekall_memory')
            ccache_filename = '%s_%s.ccache' % (base_filename, os.urandom(4).hex()) #to avoid collisions
            if len(mimi.kerberos_ccache.credentials) > 0:
                mimi.kerberos_ccache.to_file(os.path.join(directory, ccache_filename))
            for luid in mimi.logon_sessions:
                for kcred in mimi.logon_sessions[luid].kerberos_creds:
                    for ticket in kcred.tickets:
                        ticket.to_kirbi(directory)

            for cred in mimi.orphaned_creds:
                if cred.credtype == 'kerberos':
                    for ticket in cred.tickets:
                        ticket.to_kirbi(directory)

        return vol3_treegrid(mimi)
