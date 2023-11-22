import nmap
import json
import time
import argparse
import logging
import ipaddress

from zappix.sender import Sender


def addressess(network: str) -> list[str]:
    return [str(ip) for ip in ipaddress.ip_network(network, strict=False)]


def scan_host(ip: str, range: str = '1-2024', arg='-Pn') -> dict[str, list]:
    result = {}

    scanner = nmap.PortScanner()
    scanner.scan(ip, range, arguments=arg)

    for host in scanner.all_hosts():
        if scanner[host].state() == 'up':
            for proto in scanner[host].all_protocols():
                result[host] = [(port, proto) for port, val in scanner[host][proto].items() if val['state'] == 'open']

    return result


def send_metrics(zabbix_ip: str, zabbix_host: str, scan_result: dict[str, list]):
    sender = Sender(zabbix_ip)

    metrics = []
    for ip, scan_info in scan_result.items():
        for (port, proto) in scan_info:
            metric_key = f"'{ip} {port}/{proto}'"
            metrics.append(metric_key)

    logging.info(f"Sending metric for {zabbix_host}: nmap.last_scan => 0")
    res = sender.send_value(zabbix_host, 'nmap.last_scan', 0)
    print(res)

    discovery_data = []
    for metric_key in metrics:
        discovery_item = {"{#PORT}": metric_key}
        discovery_data.append(discovery_item)

    sender.send_value(zabbix_host, "nmap.discovery", json.dumps(discovery_data))

    timestamp=str(int(time.mktime(time.localtime())))

    time.sleep(10)

    for metric_key in metrics:
        logging.info(f"Sending metric for {zabbix_host}: nmap.state[{metric_key}] => {timestamp}")
        sender.send_value(zabbix_host, f"nmap.state[{metric_key}]", timestamp)

    logging.info(f"Sending metric for {zabbix_host}: nmap.last_scan => {timestamp}")
    sender.send_value(zabbix_host, 'nmap.last_scan', timestamp)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Zabbix NMAP open port monitor, author Adam Kubica <xcdr@kaizen-step.com>')

    parser.add_argument('--host', required=True, help='host the data belongs to. (this host should have the NMAP template)')
    parser.add_argument('--server', required=True, help='zabbix server', default='127.0.0.1')
    parser.add_argument('--network', required=True, help='network to scan')
    # parser.add_argument('nmap_params', nargs='+', help='NMAP parameters (in addition to -oX -)')
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)
    try:
        for address in addressess(args.network):
            logging.info(f"Scanning address: {address}")

            scan_result = scan_host(address)
            if scan_result:
                logging.info(f"Found {len(scan_result)} open ports for address: {address}")
                send_metrics(args.server, args.host, scan_result)
            else:
                logging.info(f"No open ports for address: {address}")
    except nmap.PortScannerError as e:
        logging.exception(e)
        exit(1)
    except ConnectionRefusedError as e:
        logging.exception(e)
        exit(1)
    except KeyboardInterrupt:
        exit(0)
