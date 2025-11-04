#!/usr/bin/env python3
"""
Backend API server for WHOIS lookup using python-whois (no API key needed)
This allows the HTML page to get registrar info without CORS issues
"""

from flask import Flask, request, jsonify, send_from_directory, send_file, Response
from flask_cors import CORS
import whois
import re
import os
import logging
import requests
from urllib.parse import urlparse
from werkzeug.serving import WSGIRequestHandler
import dns.resolver

# Get the directory where this script is located
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Custom request handler to filter out SSL handshake errors
class CustomRequestHandler(WSGIRequestHandler):
    def log_request(self, code='-', size='-'):
        # Only log if it's not an SSL handshake error (HTTP 400 with SSL data)
        if code == 400:
            # Check if this looks like an SSL handshake attempt
            # SSL handshakes start with \x16\x03\x01 (TLS record header)
            request_line = getattr(self, 'requestline', '')
            if isinstance(request_line, bytes):
                # Check if it starts with SSL handshake bytes
                if request_line.startswith(b'\x16\x03'):
                    return  # Don't log SSL handshake attempts
            elif isinstance(request_line, str):
                # Sometimes the request line might contain binary data
                try:
                    request_line_bytes = request_line.encode('latin-1')
                    if request_line_bytes.startswith(b'\x16\x03'):
                        return  # Don't log SSL handshake attempts
                except:
                    pass
        
        # Log normal requests
        super().log_request(code, size)
    
    def log_error(self, format, *args):
        # Suppress SSL handshake errors from being logged
        msg = format % args if args else format
        if isinstance(msg, str):
            # Check for SSL/TLS handshake indicators
            if 'Bad request version' in msg or '\x16\x03' in msg:
                return  # Don't log SSL handshake errors
        super().log_error(format, *args)
    
    def log_message(self, format, *args):
        # Suppress SSL handshake errors from being logged
        # Check both format string and formatted message
        msg = format % args if args else format
        format_str = str(format)
        
        # Check if this is an SSL handshake error
        if isinstance(msg, str):
            if 'Bad request version' in msg or '\x16\x03' in msg or (isinstance(format, bytes) and format.startswith(b'\x16\x03')):
                return  # Don't log SSL handshake errors
        
        # Also check the format string and args for SSL indicators
        if isinstance(format_str, str):
            if 'Bad request version' in format_str:
                # Check args for SSL handshake bytes
                for arg in args:
                    if isinstance(arg, (bytes, str)):
                        arg_str = arg if isinstance(arg, str) else arg.decode('latin-1', errors='ignore')
                        if '\x16\x03' in arg_str or 'Bad request version' in arg_str:
                            return  # Don't log SSL handshake errors
        
        super().log_message(format, *args)

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Configure logging to suppress SSL-related errors
logging.getLogger('werkzeug').setLevel(logging.WARNING)
# Create a custom filter to suppress SSL handshake errors
class SSLHandshakeFilter(logging.Filter):
    def filter(self, record):
        # Filter out SSL/TLS handshake errors from logs
        if hasattr(record, 'msg'):
            msg = str(record.msg)
            if 'Bad request version' in msg or 'SSL' in msg.upper() or '\x16\x03' in msg:
                return False
        return True

# Apply filter to werkzeug logger
werkzeug_logger = logging.getLogger('werkzeug')
werkzeug_logger.addFilter(SSLHandshakeFilter())

def extract_registrar_url_from_whois_text(whois_text):
    """Extract registrar URL from WHOIS raw text."""
    if not whois_text:
        return None
        
    lines = whois_text.split('\n')
    for line in lines:
        line = line.strip()
        # Try multiple patterns
        if line.startswith('Registrar URL:'):
            url = line.replace('Registrar URL:', '').strip()
            if url:
                # Preserve original protocol if present
                if not url.startswith('http'):
                    url = f"https://{url}"
                return url
        elif line.startswith('URL:'):
            url = line.replace('URL:', '').strip()
            if url:
                # Preserve original protocol if present
                if not url.startswith('http'):
                    url = f"https://{url}"
                return url
        elif 'registrar' in line.lower() and 'url' in line.lower():
            # Handle variations like "Registrar URL" or "Registrar Website URL"
            parts = line.split(':', 1)
            if len(parts) == 2:
                url = parts[1].strip()
                if url:
                    if not url.startswith('http'):
                        url = f"https://{url}"
                    return url
    return None

def check_mx_is_hostinger(domain):
    """Check if domain's MX records point to Hostinger."""
    try:
        # Query MX records for the domain
        mx_records = dns.resolver.resolve(domain, 'MX')
        
        # Check if any MX record contains 'hostinger'
        for mx in mx_records:
            mx_host = str(mx.exchange).lower()
            if 'hostinger' in mx_host:
                return True
        return False
    except Exception as e:
        # If MX lookup fails, return False (not Hostinger)
        logging.debug(f"MX lookup failed for {domain}: {str(e)}")
        return False

@app.route('/api/whois', methods=['GET'])
def get_whois_info():
    """Get WHOIS information for a domain."""
    domain = request.args.get('domain')
    
    if not domain:
        return jsonify({'error': 'Domain parameter is required'}), 400
    
    # Extract domain from email if needed
    if '@' in domain:
        domain = domain.split('@')[1]
    
    domain = domain.strip().lower()
    
    try:
        # Use python-whois library (same as your Python script)
        w = whois.whois(domain)
        
        # Extract registrar information
        registrar = None
        if hasattr(w, 'registrar') and w.registrar:
            registrar = str(w.registrar).strip()
        elif hasattr(w, 'registrar_name') and w.registrar_name:
            registrar = str(w.registrar_name).strip()
        elif hasattr(w, 'org') and w.org:
            registrar = str(w.org).strip()
        
        # Extract registrar URL from WHOIS text
        registrar_url = None
        if hasattr(w, 'text') and w.text:
            registrar_url = extract_registrar_url_from_whois_text(w.text)
        
        # Extract nameservers
        nameservers = []
        if hasattr(w, 'name_servers') and w.name_servers:
            nameservers = [str(ns).strip() for ns in w.name_servers]
        elif hasattr(w, 'nameservers') and w.nameservers:
            nameservers = [str(ns).strip() for ns in w.nameservers]
        
        # Check if Hostinger
        if registrar:
            registrar_lower = registrar.lower()
            if 'hostinger' in registrar_lower:
                return jsonify({
                    'name': 'Hostinger',
                    'website': 'hostinger'
                })
        
        # If no URL found, construct from registrar name
        if not registrar_url and registrar:
            registrar_name_clean = registrar.lower() \
                .replace(' ', '') \
                .replace('.', '') \
                .replace('inc.', '') \
                .replace('llc.', '') \
                .replace('ltd.', '') \
                .replace('corp.', '') \
                .replace('corporation', '') \
                .replace(',', '')
            registrar_url = f"https://www.{registrar_name_clean}.com"
        
        return jsonify({
            'name': registrar or 'Unknown',
            'website': registrar_url or registrar or None
        })
        
    except Exception as e:
        return jsonify({
            'error': str(e),
            'name': None,
            'website': None
        }), 500

@app.route('/favicon', methods=['GET', 'OPTIONS'])
def get_favicon():
    """
    Proxy endpoint to fetch favicon from Google's favicon service.
    Can be used as img src in HTML emails.
    
    Query parameters:
        - domain: The domain name to get favicon for (required)
        - size: Icon size (default: 128, options: 16, 32, 48, 64, 128, 256)
        - registrar: If 'true', fetch registrar's favicon instead of domain's favicon (optional)
    
    Examples:
        Domain favicon: <img src="http://91.184.248.162:8000/favicon?domain=example.com&size=64">
        Registrar favicon: <img src="http://91.184.248.162:8000/favicon?domain=example.com&registrar=true&size=64">
    """
    # Handle CORS preflight requests
    if request.method == 'OPTIONS':
        return Response(
            '',
            headers={
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Methods': 'GET, OPTIONS',
                'Access-Control-Allow-Headers': 'Content-Type',
                'Access-Control-Max-Age': '3600'
            }
        )
    
    domain = request.args.get('domain')
    size = request.args.get('size', '128')
    get_registrar = request.args.get('registrar', 'false').lower() == 'true'
    
    # Create a transparent pixel as fallback (1x1 transparent PNG)
    transparent_pixel = b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xdb\x00\x00\x00\x00IEND\xaeB`\x82'
    
    if not domain:
        # Return transparent pixel instead of JSON error for img src compatibility
        return Response(
            transparent_pixel,
            mimetype='image/png',
            headers={
                'Cache-Control': 'no-cache',
                'Access-Control-Allow-Origin': '*'
            }
        )
    
    # Extract domain from email if needed
    if '@' in domain:
        domain = domain.split('@')[1]
    
    # Clean domain
    original_domain = domain.strip().lower()
    
    # Remove protocol and www if present
    domain = original_domain.replace('http://', '').replace('https://', '').replace('www.', '')
    
    # If requesting registrar favicon, check MX first, then look it up via WHOIS
    if get_registrar:
        # First check if MX is Hostinger
        if check_mx_is_hostinger(domain):
            # MX is Hostinger, return Hostinger image
            domain = 'hostinger.com'
        else:
            # MX is not Hostinger, get registrar info
            try:
                # Get registrar website using the existing WHOIS logic
                w = whois.whois(domain)
                
                # Extract registrar URL
                registrar_url = None
                if hasattr(w, 'text') and w.text:
                    registrar_url = extract_registrar_url_from_whois_text(w.text)
                
                # If no URL found, try to get registrar name
                registrar = None
                if hasattr(w, 'registrar') and w.registrar:
                    registrar = str(w.registrar).strip()
                elif hasattr(w, 'registrar_name') and w.registrar_name:
                    registrar = str(w.registrar_name).strip()
                
                # Check if Hostinger (backup check in case MX check failed)
                if registrar and 'hostinger' in registrar.lower():
                    domain = 'hostinger.com'
                elif registrar_url:
                    # Extract domain from registrar URL
                    try:
                        if registrar_url.startswith('http://') or registrar_url.startswith('https://'):
                            parsed = urlparse(registrar_url)
                            domain = parsed.hostname or domain
                        elif '.' in registrar_url:
                            domain = registrar_url.replace('www.', '').strip()
                        else:
                            # Construct domain from registrar name
                            registrar_name_clean = (registrar or registrar_url).lower() \
                                .replace(' ', '') \
                                .replace('.', '') \
                                .replace('inc.', '') \
                                .replace('llc.', '') \
                                .replace('ltd.', '') \
                                .replace('corp.', '') \
                                .replace('corporation', '') \
                                .replace(',', '')
                            domain = f"{registrar_name_clean}.com"
                    except:
                        # If parsing fails, use original domain
                        pass
            except:
                # If WHOIS lookup fails, use original domain
                pass
    
    # Validate size parameter
    valid_sizes = ['16', '32', '48', '64', '128', '256']
    if size not in valid_sizes:
        size = '128'
    
    try:
        # URL encode the domain to handle special characters
        from urllib.parse import quote
        encoded_domain = quote(domain, safe='')
        
        # Construct Google favicon URL
        favicon_url = f"https://www.google.com/s2/favicons?domain={encoded_domain}&sz={size}"
        
        # Fetch favicon from Google
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        response = requests.get(favicon_url, headers=headers, timeout=10)
        
        if response.status_code == 200 and response.content:
            # Determine content type (default to PNG for better compatibility)
            content_type = response.headers.get('Content-Type', 'image/png')
            # If content type is not a valid image type, default to PNG
            if 'image' not in content_type.lower():
                content_type = 'image/png'
            
            # Create response with proper headers for email clients and browsers
            return Response(
                response.content,
                mimetype=content_type,
                headers={
                    'Cache-Control': 'public, max-age=86400',  # Cache for 24 hours
                    'Content-Disposition': f'inline; filename="favicon-{domain}.ico"',
                    'Access-Control-Allow-Origin': '*',
                    'Access-Control-Allow-Methods': 'GET',
                    'Access-Control-Allow-Headers': 'Content-Type'
                }
            )
        else:
            # If Google favicon service fails, return a 1x1 transparent pixel
            return Response(
                transparent_pixel,
                mimetype='image/png',
                headers={
                    'Cache-Control': 'public, max-age=3600',
                    'Access-Control-Allow-Origin': '*'
                }
            )
            
    except Exception as e:
        # Log error for debugging but still return transparent pixel
        logging.error(f"Error fetching favicon for domain {domain}: {str(e)}")
        # On error, return transparent pixel
        return Response(
            transparent_pixel,
            mimetype='image/png',
            headers={
                'Cache-Control': 'public, max-age=3600',
                'Access-Control-Allow-Origin': '*'
            }
        )

@app.route('/')
def index():
    """Serve hostinger.html"""
    html_path = os.path.join(BASE_DIR, 'hostinger.html')
    return send_file(html_path, mimetype='text/html')

@app.route('/hostinger.html')
def hostinger():
    """Serve hostinger.html"""
    html_path = os.path.join(BASE_DIR, 'hostinger.html')
    return send_file(html_path, mimetype='text/html')

if __name__ == '__main__':
    import argparse
    import ssl
    
    parser = argparse.ArgumentParser(description='WHOIS API Server')
    parser.add_argument('--port', type=int, default=8000, help='Port to run server on (default: 8000)')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to (default: 0.0.0.0)')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    parser.add_argument('--ssl', action='store_true', help='Enable HTTPS/SSL')
    parser.add_argument('--cert', default='cert.pem', help='SSL certificate file (default: cert.pem)')
    parser.add_argument('--key', default='key.pem', help='SSL private key file (default: key.pem)')
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("WHOIS API Server Started!")
    print("=" * 60)
    
    if args.ssl:
        protocol = "https"
        print(f"API Endpoint: https://{args.host}:{args.port}/api/whois?domain=example.com")
        print(f"Favicon Endpoint: https://{args.host}:{args.port}/favicon?domain=example.com&size=64")
        print(f"HTML Page: https://{args.host}:{args.port}/hostinger.html")
        print("=" * 60)
        print("SSL/HTTPS mode enabled")
        print(f"Certificate: {args.cert}")
        print(f"Private Key: {args.key}")
    else:
        protocol = "http"
        print(f"API Endpoint: http://{args.host}:{args.port}/api/whois?domain=example.com")
        print(f"Favicon Endpoint: http://{args.host}:{args.port}/favicon?domain=example.com&size=64")
        print(f"HTML Page: http://{args.host}:{args.port}/hostinger.html")
        print("=" * 60)
        print("Note: SSL/TLS handshake errors will be suppressed (server is HTTP-only)")
    
    print("=" * 60)
    print("Press Ctrl+C to stop the server")
    print("=" * 60)
    
    if args.ssl:
        # Check if certificate files exist
        if not os.path.exists(args.cert):
            print(f"ERROR: Certificate file '{args.cert}' not found!")
            print("Generate SSL certificates with:")
            print("openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes")
            exit(1)
        if not os.path.exists(args.key):
            print(f"ERROR: Private key file '{args.key}' not found!")
            print("Generate SSL certificates with:")
            print("openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes")
            exit(1)
        
        # Create SSL context
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(args.cert, args.key)
        
        app.run(
            host=args.host, 
            port=args.port, 
            debug=args.debug, 
            request_handler=CustomRequestHandler,
            ssl_context=context
        )
    else:
        app.run(host=args.host, port=args.port, debug=args.debug, request_handler=CustomRequestHandler)

