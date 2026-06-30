import os
import sys
import time
import json
import uuid
import queue
import threading
from urllib.parse import urlparse
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn

# Global Queue Manager for thread-safe operations
class QueueManager:
    def __init__(self):
        self.lock = threading.Lock()
        self.queues = {}       # queue_id -> list of messages
        self.subscribers = {}  # queue_id -> set of queue.Queue objects

    def create_queue(self):
        with self.lock:
            queue_id = uuid.uuid4().hex
            self.queues[queue_id] = []
            self.subscribers[queue_id] = set()
            return queue_id

    def send_message(self, queue_id, payload):
        with self.lock:
            if queue_id not in self.queues:
                self.queues[queue_id] = []
            if queue_id not in self.subscribers:
                self.subscribers[queue_id] = set()

            message = {
                "id": str(uuid.uuid4()),
                "payload": payload,
                "timestamp": int(time.time() * 1000)
            }
            self.queues[queue_id].append(message)
            
            # Push message to all active subscriber queues
            for sub_q in list(self.subscribers[queue_id]):
                try:
                    sub_q.put_nowait(message)
                except Exception:
                    pass
            
            return message["id"]

    def ack_message(self, queue_id, message_id):
        with self.lock:
            if queue_id in self.queues:
                initial_len = len(self.queues[queue_id])
                self.queues[queue_id] = [m for m in self.queues[queue_id] if m["id"] != message_id]
                return len(self.queues[queue_id]) < initial_len
            return False

    def add_subscriber(self, queue_id, sub_q):
        with self.lock:
            if queue_id not in self.subscribers:
                self.subscribers[queue_id] = set()
            self.subscribers[queue_id].add(sub_q)
            return list(self.queues.get(queue_id, []))

    def remove_subscriber(self, queue_id, sub_q):
        with self.lock:
            if queue_id in self.subscribers:
                self.subscribers[queue_id].discard(sub_q)

manager = QueueManager()

class CoreConnectRequestHandler(BaseHTTPRequestHandler):
    
    # Disable default logging to keep terminal output clean
    def log_message(self, format, *args):
        pass

    def send_cors_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_cors_headers()
        self.end_headers()

    def do_GET(self):
        parsed_url = urlparse(self.path)
        path = parsed_url.path

        # 1. Server-Sent Events (SSE) subscriber endpoint
        if path.startswith('/api/queue/events/'):
            queue_id = path[len('/api/queue/events/'):]
            
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.send_header('Cache-Control', 'no-cache')
            self.send_header('Connection', 'keep-alive')
            self.send_header('X-Accel-Buffering', 'no')
            self.send_cors_headers()
            self.end_headers()

            print(f"[SSE Connect] Client subscribed to Queue: {queue_id}")

            sub_q = queue.Queue()
            # Add subscriber and get currently buffered messages
            buffered_messages = manager.add_subscriber(queue_id, sub_q)

            # Flush buffered messages immediately
            try:
                for msg in buffered_messages:
                    self.wfile.write(f"data: {json.dumps(msg)}\n\n".encode('utf-8'))
                self.wfile.flush()
            except Exception as e:
                print(f"[SSE Error] Failed to write initial buffer: {e}")
                manager.remove_subscriber(queue_id, sub_q)
                return

            # Keep connection open and stream new messages
            keep_alive_time = time.time()
            try:
                while True:
                    try:
                        # Wait for a new message
                        msg = sub_q.get(timeout=2.0)
                        self.wfile.write(f"data: {json.dumps(msg)}\n\n".encode('utf-8'))
                        self.wfile.flush()
                        sub_q.task_done()
                    except queue.Empty:
                        # Send keep-alive comment to prevent socket timeout
                        if time.time() - keep_alive_time > 15:
                            self.wfile.write(b": keepalive\n\n")
                            self.wfile.flush()
                            keep_alive_time = time.time()
            except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
                pass
            except Exception as e:
                print(f"[SSE Loop Error] {e}")
            finally:
                manager.remove_subscriber(queue_id, sub_q)
                print(f"[SSE Disconnect] Client unsubscribed from Queue: {queue_id}")
            return

            return

        # 2. Static files fallback serving
        if path == '/':
            path = '/index.html'

        # Serves files from current directory
        file_path = '.' + path
        if os.path.exists(file_path) and os.path.isfile(file_path):
            self.send_response(200)
            if file_path.endswith('.html'):
                self.send_header('Content-Type', 'text/html')
            elif file_path.endswith('.css'):
                self.send_header('Content-Type', 'text/css')
            elif file_path.endswith('.js'):
                self.send_header('Content-Type', 'application/javascript')
            else:
                self.send_header('Content-Type', 'application/octet-stream')
            self.send_cors_headers()
            self.end_headers()

            with open(file_path, 'rb') as f:
                self.wfile.write(f.read())
        else:
            self.send_response(404)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(b"404 Not Found")

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length)
        
        try:
            data = json.loads(post_data.decode('utf-8')) if post_data else {}
        except Exception:
            self.send_response(400)
            self.send_cors_headers()
            self.end_headers()
            self.wfile.write(b"Invalid JSON")
            return

        # 1. Create Queue endpoint
        if self.path == '/api/queue/create':
            queue_id = manager.create_queue()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps({"queueId": queue_id}).encode('utf-8'))
            print(f"[HTTP REST] Queue Created: {queue_id}")
            return

        # 2. Send Message endpoint
        elif self.path == '/api/queue/send':
            queue_id = data.get('queueId')
            payload = data.get('payload')

            if not queue_id or not payload:
                self.send_response(400)
                self.send_cors_headers()
                self.end_headers()
                self.wfile.write(b"Missing queueId or payload")
                return

            message_id = manager.send_message(queue_id, payload)
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps({"success": True, "messageId": message_id}).encode('utf-8'))
            print(f"[HTTP REST] Msg Buffered on Queue: {queue_id}, ID: {message_id}")
            return

        # 3. Acknowledge Message endpoint
        elif self.path == '/api/queue/ack':
            queue_id = data.get('queueId')
            message_id = data.get('messageId')

            if not queue_id or not message_id:
                self.send_response(400)
                self.send_cors_headers()
                self.end_headers()
                self.wfile.write(b"Missing queueId or messageId")
                return

            success = manager.ack_message(queue_id, message_id)
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps({"success": success}).encode('utf-8'))
            if success:
                print(f"[HTTP REST] Msg Acknowledged & Deleted: {message_id} on Queue: {queue_id}")
            return

        # Not Found
        self.send_response(404)
        self.send_cors_headers()
        self.end_headers()

# Multithreaded HTTP Server to support concurrent long-lived SSE connections
class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True

def run(port=8000):
    server_address = ('0.0.0.0', port)
    httpd = ThreadedHTTPServer(server_address, CoreConnectRequestHandler)
    print(f"=================================================")
    print(f"  Core Connect Zero-Knowledge Relay running     ")
    print(f"  Listening on http://localhost:{port}          ")
    print(f"  (Includes static frontend web client)         ")
    print(f"=================================================")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping server...")
        httpd.server_close()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8000))
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            pass
    run(port)
