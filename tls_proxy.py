#!/usr/bin/env python3
"""
TLS Interception Proxy

This script implements a simple TLS interception proxy that can be used to inspect
encrypted HTTPS traffic between clients and servers.

Requirements:
- Python 3.6+
- mitmproxy

Usage:
1. Install dependencies: pip install mitmproxy
2. Create CA certificates: python tls_proxy.py --generate-ca
2. Run the proxy: python tls_proxy.py
3. Configure your client to use the proxy (default: 127.0.0.1:8080)
4. Import the CA certificate (from ~/.mitmproxy/mitmproxy-ca-cert.pem) into your browser/client
"""

import os
import sys
import logging
import argparse
import asyncio
import subprocess
from pathlib import Path

from mitmproxy import options
from mitmproxy.tools import dump
from mitmproxy import ctx
from mitmproxy import http

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger("tls_proxy")

class TLSInterceptor:
    """TLS interception add-on for mitmproxy"""
    
    def __init__(self, verbose=False):
        self.num_requests = 0
        self.verbose = verbose
    
    def load(self, loader):
        logger.info("TLS Interceptor loaded")
    
    def request(self, flow: http.HTTPFlow) -> None:
        """Process an HTTP request before sending it to the server"""
        self.num_requests += 1
        
        # Log request information
        client_ip = flow.client_conn.peername[0] if flow.client_conn.peername else "Unknown"
        url = flow.request.pretty_url
        method = flow.request.method
        
        logger.info(f"[{self.num_requests}] {client_ip}: {method} {url}")
        
        # Log request headers
        if self.verbose:
            logger.info(f"Request Headers:")
            for header, value in flow.request.headers.items():
                logger.info(f"  {header}: {value}")
        
        # Log request body if present and not too large
        if (flow.request.content and 
            len(flow.request.content) < 10000 and 
            self.verbose):
            try:
                body = flow.request.content.decode('utf-8')
                logger.info(f"Request Body:")
                logger.info(f"  {body}")
            except UnicodeDecodeError:
                logger.info(f"Request Body: Binary data ({len(flow.request.content)} bytes)")
    
    def response(self, flow: http.HTTPFlow) -> None:
        """Process an HTTP response before sending it to the client"""
        if not flow.response:
            return
            
        status = flow.response.status_code
        content_type = flow.response.headers.get("content-type", "")
        content_length = len(flow.response.content) if flow.response.content else 0
        
        logger.info(f"[{self.num_requests}] Response: {status} ({content_type}, {content_length} bytes)")
        
        # Log response headers
        if self.verbose:
            logger.info(f"Response Headers:")
            for header, value in flow.response.headers.items():
                logger.info(f"  {header}: {value}")
        
        # Log response body if text/plain or application/json and not too large
        if (flow.response.content and 
            len(flow.response.content) < 10000 and 
            ("text/" in content_type or "application/json" in content_type) and
            self.verbose):
            try:
                body = flow.response.content.decode('utf-8')
                logger.info(f"Response Body:")
                logger.info(f"  {body}")
            except UnicodeDecodeError:
                logger.info(f"Response Body: Binary data ({len(flow.response.content)} bytes)")
    
    def client_connected(self, data):
        """Called when a client connects"""
        if hasattr(data, 'client_conn') and hasattr(data.client_conn, 'peername'):
            logger.info(f"Client connected: {data.client_conn.peername}")
        else:
            logger.info("Client connected: Address unknown")
    
    def client_disconnected(self, data):
        """Called when a client disconnects"""
        if hasattr(data, 'client_conn') and hasattr(data.client_conn, 'peername'):
            logger.info(f"Client disconnected: {data.client_conn.peername}")
        else:
            logger.info("Client disconnected: Address unknown")
    
    def server_connect(self, data):
        """Called when a connection to the server is about to be established"""
        if hasattr(data, 'server_conn') and hasattr(data.server_conn, 'address'):
            logger.info(f"Server connecting: {data.server_conn.address}")
        else:
            logger.info("Server connecting: Address unknown")
    
    def server_connected(self, data):
        """Called when a connection to the server has been established"""
        if hasattr(data, 'server_conn') and hasattr(data.server_conn, 'address'):
            logger.info(f"Server connected: {data.server_conn.address}")
        else:
            logger.info("Server connected: Address unknown")
    
    def server_disconnected(self, data):
        """Called when the server connection is closed"""
        if hasattr(data, 'server_conn') and hasattr(data.server_conn, 'address'):
            logger.info(f"Server disconnected: {data.server_conn.address}")
        else:
            logger.info("Server disconnected: Address unknown")

def generate_ca_certificate():
    """Generate a new CA certificate using mitmproxy command line tools"""
    ca_path = os.path.expanduser("~/.mitmproxy")
    
    # Create the directory if it doesn't exist
    if not os.path.exists(ca_path):
        os.makedirs(ca_path)
    
    logger.info("Generating new CA certificate...")
    
    # Use the mitmproxy command to generate certificates
    try:
        # Run mitmproxy with the --set command to regenerate certificates
        subprocess.run(
            ["mitmdump", "--set", "confdir=" + ca_path, "--set", "web_open_browser=false", "--set", "listen_port=1"],
            timeout=2,  # Short timeout as we just need it to start and generate certs
            stderr=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL
        )
    except subprocess.TimeoutExpired:
        # Expected - we just needed it to start and generate certs
        pass
    
    # Check if certificate files were created
    cert_path = os.path.join(ca_path, "mitmproxy-ca-cert.pem")
    if os.path.exists(cert_path):
        logger.info(f"CA certificate generated and saved to {ca_path}")
        logger.info("You need to import this certificate into your browser or client.")
        logger.info(f"Certificate path: {cert_path}")
        
        # Also export it to other formats for different platforms
        try:
            # For Windows (DER format)
            subprocess.run(
                ["openssl", "x509", "-in", cert_path, "-outform", "DER", "-out", 
                 os.path.join(ca_path, "mitmproxy-ca-cert.cer")],
                check=True,
                stderr=subprocess.PIPE,
                stdout=subprocess.PIPE
            )
            
            # For macOS (p12 format with blank password)
            key_path = os.path.join(ca_path, "mitmproxy-ca-cert.pem")
            if os.path.exists(key_path):
                subprocess.run(
                    ["openssl", "pkcs12", "-export", "-inkey", key_path, "-in", cert_path,
                     "-out", os.path.join(ca_path, "mitmproxy-ca-cert.p12"), "-password", "pass:"],
                    check=True,
                    stderr=subprocess.PIPE,
                    stdout=subprocess.PIPE
                )
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            logger.warning(f"Could not export certificate to all formats: {str(e)}")
            logger.warning("You can still use the PEM format certificate.")
            
        return True
    else:
        logger.error("Failed to generate CA certificate.")
        return False

async def run_proxy_async(host='0.0.0.0', port=8080, verbose=False):
    """Run the TLS interception proxy with asyncio"""
    logger.info(f"Starting TLS interception proxy on {host}:{port}")
    
    # Configure mitmproxy options
    opts = options.Options(
        listen_host=host,
        listen_port=port,
        confdir=os.path.expanduser("~/.mitmproxy"),
        http2=True,
        ssl_insecure=True,  # Skip server certificate verification
    )
    
    # Create and configure the proxy server with the current event loop
    master = dump.DumpMaster(
        opts,
        with_termlog=verbose,
        with_dumper=verbose,
    )
    
    # Add our custom interceptor
    master.addons.add(TLSInterceptor(verbose=verbose))
    
    # Start the master
    await master.run()
    
    return master

def run_proxy(host='0.0.0.0', port=8080, verbose=False):
    """Run the proxy server with proper asyncio setup"""
    try:
        # Create and configure a new event loop
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        # Run the proxy in the event loop
        master = loop.run_until_complete(run_proxy_async(host, port, verbose))
        
        try:
            # Keep the loop running
            loop.run_forever()
        except KeyboardInterrupt:
            logger.info("Proxy server interrupted.")
        finally:
            # Shutdown master
            if master:
                master.shutdown()
            
            # Close the event loop
            loop.close()
            
    except KeyboardInterrupt:
        logger.info("Proxy server interrupted.")

def check_cert_exists():
    """Check if the mitmproxy certificate exists"""
    ca_path = os.path.expanduser("~/.mitmproxy/mitmproxy-ca-cert.pem")
    return os.path.exists(ca_path)

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="TLS Interception Proxy")
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind the proxy (default: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=8080, help='Port to bind the proxy (default: 8080)')
    parser.add_argument('--generate-ca', action='store_true', help='Generate a new CA certificate')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose logging')
    
    args = parser.parse_args()
    
    if args.generate_ca:
        if generate_ca_certificate():
            logger.info("CA certificate generated successfully.")
        else:
            logger.error("Failed to generate CA certificate.")
        return
    
    # Check if CA certificate exists
    if not check_cert_exists():
        logger.warning("CA certificate not found. This will be automatically generated when you first run mitmproxy.")
        response = input("Generate CA certificate now? (y/n): ")
        if response.lower() == 'y':
            generate_ca_certificate()
        else:
            logger.warning("Continuing without checking for CA certificate.")
    
    # Run the proxy server
    run_proxy(args.host, args.port, args.verbose)

if __name__ == "__main__":
    main()