import volatility3.framework.interfaces.plugins as plugins
from volatility3.framework import renderers
from volatility3.framework.configuration import requirements
from volatility3.framework import contexts
from volatility3.plugins.windows.netstat import Netstat
import volatility3.framework.interfaces.plugins as interfaces
import volatility3.framework.objects as obj
import logging


# Define common ports (HTTP, HTTPS, SSH)
COMMON_PORTS = [80, 443, 22]

def is_common_port(port):
    """Check if the port is common (HTTP, HTTPS, SSH)."""
    return port in COMMON_PORTS


class SimpleNetScan(plugins.PluginInterface):
    """Plugin for scanning network connections using uncommon ports."""
    
    # Set the required configuration for the plugin (requires memory image and symbol path)
    _required_configuration = [
        requirements.MemmapRequirement(name="memory", description="Memory image file", optional=False),
        requirements.StringRequirement(name="symbol_path", description="Symbol path", optional=False)
    ]
    
    def __init__(self, context: contexts.Context, config_path: str = None, **kwargs):
        """Initialize the plugin."""
        super().__init__(context, config_path, **kwargs)
        self.context = context
        self.config_path = config_path
    
    def _scan_uncommon_ports(self):
        """Scan network connections and identify those with uncommon ports."""
        # Run the Netstat plugin to get network connections
        netstat_plugin = Netstat(context=self.context, config_path=self.config_path)
        connections = netstat_plugin.calculate()

        # Filter out connections with common ports
        uncommon_connections = []

        for connection in connections:
            # Extract relevant details: local port, foreign port, IP addresses, and process ID
            local_ip = connection.local_ip
            local_port = connection.local_port
            foreign_ip = connection.foreign_ip
            foreign_port = connection.foreign_port
            pid = connection.pid
            
            # Check if the port is uncommon (i.e., not in the list of common ports)
            if not is_common_port(local_port) and not is_common_port(foreign_port):
                uncommon_connections.append({
                    'pid': pid,
                    'local_ip': local_ip,
                    'local_port': local_port,
                    'foreign_ip': foreign_ip,
                    'foreign_port': foreign_port
                })
        
        return uncommon_connections
    
    def _run(self):
        """Run the plugin and display results."""
        # Scan for uncommon network connections
        uncommon_connections = self._scan_uncommon_ports()

        # Output results
        if uncommon_connections:
            output = f"{'PID':<10} {'Local IP':<15} {'Local Port':<12} {'Foreign IP':<15} {'Foreign Port':<12}\n"
            output += "=" * 64 + "\n"
            for conn in uncommon_connections:
                output += f"{conn['pid']:<10} {conn['local_ip']:<15} {conn['local_port']:<12} {conn['foreign_ip']:<15} {conn['foreign_port']:<12}\n"
        else:
            output = "No uncommon connections found.\n"

        return output
    
    def run(self):
        """Runs the scan and prints the results."""
        result = self._run()
        print(result)


# To use this plugin, we need to add it to Volatility3's plugin system
# If you were to execute this in the Volatility3 framework, the system would load the plugin as follows:
# vol -p ./plugins/windows -f memory_image.vmem simple_netscan.SimpleNetScan
