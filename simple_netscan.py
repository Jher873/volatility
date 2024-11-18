from volatility3.framework import interfaces, renderers, constants
from volatility3.framework.configuration import requirements
from volatility3.plugins.windows import netscan
from volatility3.framework.renderers import format_hints

# Define the common ports for web and SSH
COMMON_PORTS = [80, 443, 22]

class SimpleNetScan(interfaces.plugins.PluginInterface):
    @classmethod
    def get_requirements(cls):
        # Specify the requirements for the plugin: the memory image and the netstat data
        return [
            requirements.Requirement(
                "memory",
                description="The memory image to analyze"
            ),
            requirements.Requirement(
                "netscan",  # Dependency to scan the network connections
                description="The network connections found in the memory image"
            )
        ]

    def _generator(self, connections):
        """
        Generator that filters network connections based on uncommon ports.
        """
        for connection in connections:
            # Extract information from the connection object
            pid = connection.pid
            local_ip = connection.local_address
            local_port = connection.local_port
            foreign_ip = connection.remote_address
            foreign_port = connection.remote_port

            # Check if the local port is not in the list of common ports
            if local_port not in COMMON_PORTS:
                yield {
                    "pid": pid,
                    "local_ip": local_ip,
                    "local_port": local_port,
                    "foreign_ip": foreign_ip,
                    "foreign_port": foreign_port,
                }

    def run(self):
        # Use the netscan plugin to gather network connections from the memory image
        net_connections = netscan.NetScan(self._config)
        connections = net_connections.calculate()

        # Display only the essential information for connections with uncommon ports
        results = list(self._generator(connections))

        if not results:
            print("No uncommon network connections found.")
            return
        
        # Render results in a simple tabular format
        for result in results:
            print(f"PID: {result['pid']}, Local IP: {result['local_ip']}, Local Port: {result['local_port']}, "
                  f"Foreign IP: {result['foreign_ip']}, Foreign Port: {result['foreign_port']}")
