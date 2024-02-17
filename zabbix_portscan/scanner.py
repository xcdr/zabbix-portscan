import nmap
import json
import time
import argparse
import logging

from zabbix_utils import Sender


# Scan network for specified port range
def scan(network: str, range: str = '1-65535', args='') -> dict[str, list]:
    result = {}
    scanner = nmap.PortScanner()
    scanner.scan(network, range, arguments=args)

    for host in scanner.all_hosts():
        if scanner[host].state() == 'up':
            for proto in scanner[host].all_protocols():
                result[host] = [(port, proto) for port, val in scanner[host][proto].items() if val['state'] == 'open']

    return result


# Send metrics to zabbix server
def send_metrics(zabbix_ip: str, zabbix_host: str, scan_result: dict[str, list]):
    sender = Sender(zabbix_ip)

    metrics = []
    for ip, scan_info in scan_result.items():
        for (port, proto) in scan_info:
            metric_key = f"'{ip} {port}/{proto}'"
            metrics.append(metric_key)

    discovery_data = []
    for metric_key in metrics:
        discovery_item = {"{#PORT}": metric_key}
        discovery_data.append(discovery_item)

    sender.send_value(zabbix_host, "nmap.discovery", json.dumps(discovery_data))

    time.sleep(10)

    timestamp = str(int(time.mktime(time.localtime())))

    for metric_key in metrics:
        logging.info(f"Sending metric for {zabbix_host}: nmap.state[{metric_key}] => {timestamp}")
        sender.send_value(zabbix_host, f"nmap.state[{metric_key}]", timestamp)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Zabbix open port monitor, author Adam Kubica <xcdr@kaizen-step.com>')

    parser.add_argument('--host', required=True,
                        help='host the data belongs to. (this host should have the NMAP template)')
    parser.add_argument('--server', required=True,
                        help='zabbix server (default: 127.0.0.1)', default='127.0.0.1')
    parser.add_argument('--network', required=True,
                        help='network to scan')
    parser.add_argument('--ports', required=False,
                        help='ports to scan (default: 1-1024)', default='1-1024')
    parser.add_argument('--verbose', required=False, default=False, action=argparse.BooleanOptionalAction,
                        help='log info to stdout')
    parser.add_argument('nmap_params', nargs='*',
                        help='additional NMAP parameters')
    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.INFO)

    try:
        logging.info(f"Start scan for: {args.network}")
        scan_result = scan(args.network, range=args.ports, args=' '.join(args.nmap_params))
        if scan_result:
            logging.info(f"Found {len(scan_result)} open ports for: {args.network}")
            send_metrics(args.server, args.host, scan_result)
        else:
            logging.info(f"No open ports for: {args.network}")
    except nmap.PortScannerError as e:
        logging.error(e)
        exit(1)
    except (ConnectionRefusedError, OSError) as e:
        logging.error(e)
        exit(1)
    except KeyboardInterrupt:
        exit(0)
