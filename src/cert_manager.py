#!/usr/bin/env python3
"""
Application TLS Certificate Manager

Obtains an initial certificate using a bootstrap token, then automatically
renews it 30 days before expiry by presenting the current certificate to
the provisioning server.
"""

import json
import logging
import os
import sys
import time
import signal
from datetime import datetime, timezone
from pathlib import Path

import docker
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
    stream=sys.stdout,
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration from environment
# ---------------------------------------------------------------------------
CA_URL     	    = os.environ["CA_URL"]           # required
CLIENT_CN           = os.environ.get("CLIENT_NAME", "unknown")
CLIENT_DOMAIN	    = os.environ.get("CLIENT_DOMAIN", "example.org")
CLIENT_OU           = os.environ.get("CLIENT_OU", "")
CLIENT_O            = os.environ.get("CLIENT_O", "")
CLIENT_C            = os.environ.get("CLIENT_C", "")
CERT_DIR            = Path(os.environ.get("CERT_DIR", "/certs"))
# Token: prefer env-var; fall back to a file (handy with Docker secrets)
INITIAL_TOKEN       = os.environ.get("INITIAL_TOKEN", "")
TOKEN_FILE          = Path(os.environ.get("TOKEN_FILE", "/run/secrets/initial_token"))
RESTART_CONTAINER   = os.environ.get("RESTART_CONTAINER", "")
RESTART_PIDFILE     = Path(os.environ.get("PID_FILE", ""))
RESTART_SIGNAL      = os.environ.get("RESTART_SIGNAL", "-1")
# How many seconds between routine checks (default: every 12 h)
CHECK_INTERVAL_SEC  = int(os.environ.get("CHECK_INTERVAL_SEC", str(12 * 3600)))
# Renew when this many days remain before expiry
RENEWAL_DAYS        = int(os.environ.get("RENEWAL_DAYS", "30"))
# Optional: extra CA bundle to verify the provisioning server's TLS cert
CERT_SERVER_CA      = os.environ.get("CERT_SERVER_CA", "")    # path or ""
# Key size for generated RSA keys
KEY_BITS            = int(os.environ.get("KEY_BITS", "2048"))

# Paths inside CERT_DIR
KEY_FILE  = CERT_DIR / "client.key"
CERT_FILE = CERT_DIR / "client.crt"
CA_FILE   = CERT_DIR / "ca.crt"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def read_token() -> str:
    """Return the bootstrap token from env-var or token file."""
    if INITIAL_TOKEN:
        return INITIAL_TOKEN
    if TOKEN_FILE.exists():
        token = TOKEN_FILE.read_text().strip()
        if token:
            return token
    raise RuntimeError(
        "No initial token found. Set INITIAL_TOKEN env-var or mount a token "
        f"file at {TOKEN_FILE} (or override TOKEN_FILE)."
    )


def generate_key_and_csr() -> tuple[str, str]:
    """Generate a fresh RSA private key and a matching CSR."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=KEY_BITS)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name([
              x509.NameAttribute(NameOID.COMMON_NAME,              CLIENT_CN),
              x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, CLIENT_OU),
              x509.NameAttribute(NameOID.ORGANIZATION_NAME,        CLIENT_O),
              x509.NameAttribute(NameOID.COUNTRY_NAME,             CLIENT_C),
            ])
        )
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(f"{CLIENT_CN}.{CLIENT_DOMAIN}"),
            ]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode()
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()
    return key_pem, csr_pem


def request_certificate(csr_pem: str, *, token: str | None = None,
                        current_cert_pem: str | None = None) -> dict:
    """POST a CSR to the provisioning server; return parsed JSON response."""
    if token is not None:
        payload = {"csr": csr_pem, "token": token}
        log.info("Requesting initial certificate (token auth).")
    elif current_cert_pem is not None:
        payload = {"csr": csr_pem, "cert": current_cert_pem}
        log.info("Requesting certificate renewal (cert auth).")
    else:
        raise ValueError("Provide either token or current_cert_pem.")

    resp = requests.post(
        CA_URL,
        json=payload,
        timeout=30,
    )
    resp.raise_for_status()
    data = resp.json()

    # Validate expected keys
    for key in ("certificate", "ca_certificate", "client_name"):
        if key not in data:
            raise ValueError(f"Provisioning server response missing key: {key!r}")

    log.info("Certificate issued for client_name=%r", data["client_name"])
    return data


def save_certificates(key_pem: str, data: dict) -> None:
    """Atomically write key, certificate, and CA certificate to CERT_DIR."""
    CERT_DIR.mkdir(parents=True, exist_ok=True)

    # Write via temp files then rename for atomicity
    def _write(path: Path, content: str, mode: int = 0o644, set_group: bool = False) -> None:
        tmp = path.with_suffix(".tmp")
        tmp.write_text(content)
        tmp.chmod(mode)
        if set_group:
          try:
            import grp
            gid = grp.getgrnam("certreaders").gr_gid
            os.chown(tmp, -1, gid)
          except KeyError:
            log.warning("Group 'certreaders' not found; private key will be owner-readable only (600).")
            tmp.chmod(0o600)
        tmp.rename(path)

    _write(KEY_FILE,  key_pem,   mode=0o640, set_group=True)
    _write(CERT_FILE, data["certificate"])
    _write(CA_FILE,   data["ca_certificate"])
    log.info("Certificates written to %s", CERT_DIR)

def cert_expiry_days() -> int | None:
    """
    Return days until the current certificate expires, or None if no cert.
    """
    if not CERT_FILE.exists():
        return None
    cert = x509.load_pem_x509_certificate(CERT_FILE.read_bytes())
    now = datetime.now(timezone.utc)
    # cryptography ≥ 42 exposes not_valid_after_utc; fall back for older builds
    try:
        expiry = cert.not_valid_after_utc
    except AttributeError:
        expiry = cert.not_valid_after.replace(tzinfo=timezone.utc)
    return (expiry - now).days


def restart_app() -> None:
    """Restart the application container or process so it picks up the new certificates."""
    if RESTART_CONTAINER:
        try:
            client = docker.from_env()
            container = client.containers.get(RESTART_CONTAINER)
            container.restart(timeout=10)
            log.info("Restarted container %r.", RESTART_CONTAINER)
        except docker.errors.NotFound:
            log.warning(
                "Container %r not found — application may not be running yet.",
                RESTART_CONTAINER,
            )
        except Exception as exc:
            log.error("Failed to restart application container: %s", exc)
    elif RESTART_PIDFILE:
        try:
            with open(RESTART_PIDFILE, 'r') as f:
                pid = int(f.read().strip())
        except FileNotFoundError:
            log.info(f"PID file not found: {RESTART_PIDFILE}")
            return
        except ValueError:
            log.info(f"Invalid PID in file: {RESTART_PIDFILE}")
            return

        try:
            sig = int(RESTART_SIGNAL)          # try numeric first: "9", "15", etc.
            if (sig<0): sig=-sig
        except ValueError:
            try:
                sig = getattr(signal, RESTART_SIGNAL)   # fall back to name: "SIGHUP", "SIGTERM"
            except AttributeError:
                log.error(f"Unknown signal: {RESTART_SIGNAL!r}. Use a number (9) or name (SIGHUP)")

        try:
            os.kill(pid, sig)
        except ProcessLookupError:
            log.info(f"No process with PID {pid} to be restarted")
        except PermissionError:
            log.info(f"No permission to signal PID {pid}")
    else:
        log.info("Nothing restarted (no PID-file nor container name specified).")

# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def run_once() -> bool:
    """
    Check certificate validity and renew if necessary.
    Returns True if a renewal was performed.
    """

    days = cert_expiry_days()
    use_token = True
    if days is None:
        log.info("Certificate check: no certificate on disk")
    elif days <= 0:
        log.info(f"Certificate check: certificate already expired ({days}d)")
    elif days <= RENEWAL_DAYS:
        log.info(f"Certificate check: certificate expires in {days} day(s) (threshold: {RENEWAL_DAYS}d)")
        use_token = False
    else:
        log.info(f"certificate valid for {days} more day(s)")
        return False

    log.info("Starting certificate issuance/renewal…")
    key_pem, csr_pem = generate_key_and_csr()

    if use_token:
        # First-time bootstrap: use the token
        token = read_token()
        data = request_certificate(csr_pem, token=token)
    else:
        # Renewal: present the current certificate
        current_cert_pem = CERT_FILE.read_text()
        data = request_certificate(csr_pem, current_cert_pem=current_cert_pem)

    save_certificates(key_pem, data)
    restart_app()
    return True

class RestartLoop(Exception):
    pass

def handle_signal(signum, frame):
    raise RestartLoop()

def main() -> None:
    log.info(
        "cert-manager starting | server=%s cn=%s renewal_threshold=%dd",
        CA_URL, CLIENT_CN, RENEWAL_DAYS,
    )

    # On the very first run, retry quickly if the network isn't ready yet
    retry_delay = 30  # seconds
    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGHUP, handle_signal)
    while True:
        try:
            run_once()
            retry_delay = 30   # reset on success
        except requests.HTTPError as exc:
            log.error("HTTP error from provisioning server: %s", exc)
            log.info("Retrying in %d s…", retry_delay)
            time.sleep(retry_delay)
            retry_delay = min(retry_delay + retry_delay/2, 3600)
            continue
        except Exception as exc:
            log.error("Unexpected error during certificate operation: %s", exc, exc_info=True)
            log.info("Retrying in %d s…", retry_delay)
            time.sleep(retry_delay)
            retry_delay = min(retry_delay * 2, 3600)
            continue
        except RestartLoop:
            print("Restarted by signal")
            retry_delay = 30
            continue  # jumps back to the top of the while loop

        try:
            log.info("Next check in %d s.", CHECK_INTERVAL_SEC)
            time.sleep(CHECK_INTERVAL_SEC)
        except RestartLoop:
            print("Restarted by signal")
            retry_delay = 30
            continue  # jumps back to the top of the while loop


if __name__ == "__main__":
    main()
