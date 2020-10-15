import time
import click
from zapv2 import ZAPv2
from pprint import pprint

@click.command()
@click.option('-k', '--api-key', type=str, help="API key")
@click.option('-t', '--target-url', type=str, required=True, help="API key")
def zap_scan(**kwargs):
    # The URL of the application to be tested
    target_url = kwargs.pop('target_url', None)
    apiKey = kwargs.pop('api_key', None)

    # By default ZAP API client will connect to port 8080
    # zap = ZAPv2(apikey=apiKey)
    # Use the line below if ZAP is not listening on port 8080, for example, if listening on port 8090
    zap = ZAPv2(apikey=apiKey, proxies={'http': 'http://127.0.0.1:8181', 'https': 'http://127.0.0.1:8181'})

    # Scanning the URL
    print('Spidering target {}'.format(target_url))

    scanID = zap.spider.scan(url=target_url)
    time.sleep(5)
    print(zap.spider.status(scanID))

    while int(zap.spider.status(scanID)) < 100:
        # Poll the status until it completes
        print('Spider progress %: {}'.format(zap.spider.status(scanID)))
        time.sleep(1)

    print('Spider has completed!')
    # Prints the URLs the spider has crawled
    print('\n'.join(map(str, zap.spider.results(scanID))))
    # If required post process the spider results

    # TODO: Explore the Application more with Ajax Spider or Start scanning the application for vulnerabilities

    while int(zap.pscan.records_to_scan) > 0:
        # Loop until the passive scan has finished
        print('Records to passive scan : ' + zap.pscan.records_to_scan)
        time.sleep(2)

    print('Passive Scan completed')

    # Print Passive scan results/alerts
    print('Hosts: {}'.format(', '.join(zap.core.hosts)))
    print('Alerts: ')
    pprint(zap.core.alerts())

    # TODO : explore the app (Spider, etc) before using the Active Scan API, Refer the explore section
    print('Active Scanning target {}'.format(target_url))
    scanID = zap.ascan.scan(target_url)
    while int(zap.ascan.status(scanID)) < 100:
        # Loop until the scanner has finished
        print('Scan progress %: {}'.format(zap.ascan.status(scanID)))
        time.sleep(5)

    print('Active Scan completed')
    # Print vulnerabilities found by the scanning
    print('Hosts: {}'.format(', '.join(zap.core.hosts)))
    print('Alerts: ')
    pprint(zap.core.alerts(baseurl=target_url))

if __name__ == "__main__":
    zap_scan()
