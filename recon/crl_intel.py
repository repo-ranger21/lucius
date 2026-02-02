import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend


def download_crl(url="https://api.nnip.com/NC-PDROOTCA-1.crl"):
    response = requests.get(url)
    response.raise_for_status()  # Raise an error for bad responses
    return response.content


def parse_crl(crl_data):
    crl = x509.load_pem_x509_crl(crl_data, default_backend())
    decommissioned_hostnames = []
    for revoked in crl.get_revoked_certificates():
        serial_number = revoked.serial_number
        subject = revoked.subject
        decommissioned_hostnames.append((serial_number, subject))
    return decommissioned_hostnames


def get_decommissioned_hostnames(url="https://api.nnip.com/NC-PDROOTCA-1.crl"):
    crl_data = download_crl(url)
    return parse_crl(crl_data)
