import threading
import time
import os
from mininet.log import info

class StatsLogger:
    """A class to log network interface statistics in a background thread."""

    def __init__(self, net, log_file="network_stats.log", interval=10):
        self.net = net
        self.log_file = log_file
        self.interval = interval
        self.running = False
        self.thread = threading.Thread(target=self._log_loop)

        # Clear the log file and write the header at the start
        with open(self.log_file, "w") as f:
            f.write("timestamp,link,tx_bytes,rx_bytes,tx_dropped,rx_dropped\n")

    def _get_intf_stats(self, intf_name):
        """Reads statistics for a given interface from the /sys filesystem."""
        stats = {}
        try:
            with open(f"/sys/class/net/{intf_name}/statistics/tx_bytes", "r") as f:
                stats['tx_bytes'] = int(f.read().strip())
            with open(f"/sys/class/net/{intf_name}/statistics/rx_bytes", "r") as f:
                stats['rx_bytes'] = int(f.read().strip())
            with open(f"/sys/class/net/{intf_name}/statistics/tx_dropped", "r") as f:
                stats['tx_dropped'] = int(f.read().strip())
            with open(f"/sys/class/net/{intf_name}/statistics/rx_dropped", "r") as f:
                stats['rx_dropped'] = int(f.read().strip())
        except FileNotFoundError:
            return None # Interface might not exist
        return stats

    def _log_loop(self):
        """The main logging loop that runs in the background."""
        while self.running:
            timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
            log_entries = []
            
            for link in self.net.links:
                intf1_name = link.intf1.name
                intf2_name = link.intf2.name
                
                stats1 = self._get_intf_stats(intf1_name)
                
                if stats1:
                    link_name = f"{intf1_name}-{intf2_name}"
                    log_entries.append(
                        f"{timestamp},{link_name},"
                        f"{stats1['tx_bytes']},{stats1['rx_bytes']},"
                        f"{stats1['tx_dropped']},{stats1['rx_dropped']}\n"
                    )

            if log_entries:
                with open(self.log_file, "a") as f:
                    f.writelines(log_entries)

            time.sleep(self.interval)

    def start(self):
        """Starts the background logging thread."""
        info(f'*** Starting network stats logger (interval: {self.interval}s, output: {self.log_file})\n')
        self.running = True
        self.thread.start()

    def stop(self):
        """Stops the background logging thread."""
        info('*** Stopping network stats logger...\n')
        self.running = False
        self.thread.join()
