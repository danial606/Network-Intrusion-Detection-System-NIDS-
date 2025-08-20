import http.server
import socketserver

PORT = 80
Handler = http.server.SimpleHTTPRequestHandler

try:
    with socketserver.TCPServer(("", PORT), Handler) as httpd:
        print("Dummy server running on port", PORT)
        print("Press Ctrl+C to stop the server.")
        httpd.serve_forever()
except OSError:
    print(f"Could not start server on port {PORT}.")
    print("Please ensure no other service (like IIS, Apache, or another web server) is using it, and that you are running this script with Administrator/sudo privileges.")
except KeyboardInterrupt:
    print("\nServer stopped.")