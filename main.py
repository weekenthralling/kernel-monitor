import argparse
import json
import logging
import socket
import base64
import os
import threading
import time
from datetime import datetime
from Cryptodome.Cipher import AES, PKCS1_v1_5
from Cryptodome.PublicKey import RSA
from Cryptodome.Util.Padding import unpad

from kubernetes import client, config
from kubernetes.client.rest import ApiException
from jupyter_client.blocking import BlockingKernelClient

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

logging.basicConfig(level=LOG_LEVEL)
logger = logging.getLogger(__name__)


def decrypt(payload_b64: bytes, private_key: str) -> str:
    """Decrypt payload and return the connection information."""
    # Decode the Base64 payload
    payload = str(base64.b64decode(payload_b64), "utf-8")
    payload = json.loads(payload)

    # Extract encrypted AES key and connection info
    encrypted_key = base64.b64decode(payload["key"])
    b64_connection_info = base64.b64decode(payload["conn_info"])

    # Decrypt AES key using RSA private key
    private_key_obj = RSA.importKey(base64.b64decode(private_key.encode()))
    cipher_rsa = PKCS1_v1_5.new(private_key_obj)
    aes_key = cipher_rsa.decrypt(encrypted_key, None)

    if aes_key is None:
        raise ValueError("Failed to decrypt the AES key. Check the private key.")

    # Decrypt the connection info using AES
    cipher_aes = AES.new(aes_key, AES.MODE_ECB)
    connection_info = unpad(cipher_aes.decrypt(b64_connection_info), 16)
    return connection_info.decode("utf-8")


def update_cr_resource(
    namespace: str,
    cr_name: str,
    labels: dict | None = None,
    annotations: dict | None = None,
) -> None:
    """Update Kubernetes CRD labels or annotation with multiple key-value pairs."""
    if not labels and not annotations:
        logger.error("No labels or annotations provided to update.")
        return

    # Load kubeconfig to configure Kubernetes client
    try:
        config.load_incluster_config()
    except config.ConfigException:
        config.load_kube_config()

    api_instance = client.CustomObjectsApi()

    # Fetch the current CRD object
    crd = api_instance.get_namespaced_custom_object(
        group="jupyter.org",
        version="v1",
        namespace=namespace,
        plural="kernels",
        name=cr_name,
    )

    if labels:
        # Retrieve existing labels, if any
        _labels = crd.get("metadata", {}).get("labels", {})
        # Update labels with new key-value pairs
        _labels.update(labels)
        # Set the updated labels back to the CRD
        crd["metadata"]["labels"] = _labels

    if annotations:
        # Retrieve existing annotations, if any
        _annotations = crd.get("metadata", {}).get("annotations", {})
        # Update annotations with new key-value pairs
        _annotations.update(annotations)
        # Set the updated annotations back to the CRD
        crd["metadata"]["annotations"] = _annotations

    # Replace the CRD with updated labels
    api_instance.replace_namespaced_custom_object(
        group="jupyter.org",
        version="v1",
        namespace=namespace,
        plural="kernels",
        name=cr_name,
        body=crd,
    )
    logger.info(f"Successfully updated labels for {cr_name}.")


def listen_kernel_creation(host="127.0.0.1", port=65432) -> str:
    """Listen for kernel creation requests and return connection information."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)

    try:
        while True:
            client_socket, _ = server_socket.accept()
            data = ""
            with client_socket:
                while True:
                    buffer = client_socket.recv(1024).decode("utf-8")
                    if not buffer:
                        break  # End communication if no data is received
                    data += buffer
            # Decrypt and return the connection_info
            return decrypt(data.encode("utf-8"), private_key)
    except KeyboardInterrupt:
        logging.error("\nServer is shutting down...")
    finally:
        server_socket.close()
        logging.debug("Server has been closed.")


class KernelMonitor:
    def __init__(
        self,
        namespace: str,
        cr_name: str,
        connection_info: dict,
        idle_timeout: int,
        culling_interval: int,
    ):
        self.namespace = namespace
        self.cr_name = cr_name
        self.connection_info = connection_info
        self.idle_timeout = idle_timeout
        self.culling_interval = culling_interval

        # Initialize kernel client and monitor last activity time
        self.client = BlockingKernelClient()
        self.client.load_connection_info(self.connection_info)
        # Sidecar should wait for kernel to be ready
        logger.info("Wait for kernel ready...")
        self.client.wait_for_ready()
        self.client.start_channels()
        logger.info("Kernel is ready, starting monitor...")

        # Set last activity timestamp to current time if kernel is ready
        self.last_activity_timestamp = time.time()
        self.lock = threading.Lock()

    def update_last_activity(self):
        with self.lock:
            self.last_activity_timestamp = time.time()
        annotations = {
            "jupyter.org/lastActivityTime": str(datetime.now()),
        }
        update_cr_resource(
            namespace=self.namespace, cr_name=self.cr_name, annotations=annotations
        )

    def monitor_activity(self) -> None:
        """Monitor kernel activity and idle time."""
        while True:
            try:
                msg = self.client.get_iopub_msg(timeout=1)
                if (
                    msg
                    and msg["header"]["msg_type"] == "status"
                    and msg["content"]["execution_state"] == "busy"
                ):
                    # Kernel is busy, update last activity timestamp
                    logger.debug("Kernel is busy, updating last activity timestamp.")
                    self.update_last_activity()
            except Exception:
                logger.debug("No message received from kernel.")
                pass

    def start(self):
        threading.Thread(target=self.monitor_activity, daemon=True).start()
        while True:
            current_time = time.time()
            with self.lock:
                idle_time = current_time - self.last_activity_timestamp
            if idle_time > self.idle_timeout:
                labels = {"jupyter.org/kernelmanager-idle": "true"}
                try:
                    update_cr_resource(
                        namespace=self.namespace, cr_name=self.cr_name, labels=labels
                    )
                except ApiException as e:
                    logger.error(f"Failed to update CR label: {e}")
            time.sleep(self.culling_interval)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Kernel monitor for Jupyter kernel.")
    parser.add_argument(
        "--idle-timeout", type=int, default=3600, help="Kernel idle timeout."
    )
    parser.add_argument(
        "--culling-interval", type=int, default=60, help="Kernel culling interval."
    )
    parser.add_argument(
        "--private-key",
        required=True,
        help="Private key to decrypt the connection info.",
    )

    args = parser.parse_args()

    # Load environment variables
    name = os.getenv("NAME")
    namespace = os.getenv("NAMESPACE")
    real_IP = os.getenv("IP")

    if namespace is None:
        raise ValueError("NAMESPACE is not set in environment variables.")

    if name is None:
        raise ValueError("CRD NAME is not set in environment variables.")

    logger.info("Kernel name: %s", name)
    logger.info("Namespace: %s", namespace)
    logger.info("Kernel idle timeout: %s", args.idle_timeout)
    logger.info("Kernel culling interval: %s", args.culling_interval)

    private_key = args.private_key
    connection_info = listen_kernel_creation()

    connection_info = json.loads(connection_info)
    connection_info = connection_info | {"ip": real_IP}
    # Update kernel annotation set connection to this instance
    update_cr_resource(
        namespace, name, annotations={"jupyter.org/kernel-connection": connection_info}
    )

    monitor = KernelMonitor(
        namespace, name, connection_info, args.idle_timeout, args.culling_interval
    )
    monitor.start()
