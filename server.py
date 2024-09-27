import socketserver
from util.request import Request
from util.router import Router
import os
from util.hello_path import hello_path


class MyTCPHandler(socketserver.BaseRequestHandler):
#INITIALIZES ROUTER OBJECT
#ADDS ROUTES TO ROUTER OBJECT
#LOADS FILES INTO DICTIONARY
#CALLS LOADS FILES to LOAD FILES INTO DICTIONARY

    def __init__(self, request, client_address, server):
        self.router = Router()
        self.router.add_route("GET", "/", self.index_path, True)
        self.router.add_route("GET", "/style.css", self.css_path, True)
        self.router.add_route("GET", "/webrtc.js", self.js_path, True)
        self.router.add_route("GET", "/image/<image_name>", self.image_path, True)

        self.files = {
            "index.html": "text/html",
            "style.css": "text/css",
            "webrtc.js": "application/javascript",
            "image/elephant.jpg": "image/jpg",
            "image/flamingo.jpg": "image/jpg",
            "image/kitten.jpg": "image/jpg",
            "image/cat.jpg": "image/jpg",
            "image/dog.jpg": "image/jpg",
            "image/eagle.jpg": "image/jpg",
            "image/elephant-small.jpg": "image/jpg",
        }
        self.loaded_files = {}
        self.load_files()
        super().__init__(request, client_address, server)


#HANDLE READS DATA FROM CLIENT(BROWSER)
#CREEATES REQUEST OBJECT TO PARSE USING REUEST.PY
#USES ROUTER.PY TO ROUTE REQUEST TO ITS APPROPIATE HANDLER FUNCTION
#HANDLER FUNCTION SENDS RESPONSE TO CLIENT(BROWSER)

    def handle(self):
        received_data = self.request.recv(2048)
        print(self.client_address)
        print("--- received data ---")
        print(received_data)
        print("--- end of data ---\n\n")
        request = Request(received_data)
        self.router.route_request(request, self)

#LOADS FILES INTO DICTIONARY
#OPENS FILES IN READ BINARY MODE
#READS CONTENT OF FILE
#STORES CONTENT OF FILE IN DICTIONARY
    def load_files(self):
        for filename, content_type in self.files.items():
            file_path = os.path.join("public", filename)  # Construct the full file path
            try:
                with open(file_path, 'rb') as f:
                    content = f.read()
                    self.loaded_files[filename] = {
                        "content": content,
                        "content_type": content_type
                    }
            except FileNotFoundError:
                print(f"File not found: {file_path}")
            except Exception as e:
                print(f"Error loading {filename}: {e}")

#HANDLES INDEX PATH
    def index_path(self, request, handler):
        cookie_header = request.headers.get("Cookie")
        visit_count=1




        if "index.html" in self.loaded_files:
            content = self.loaded_files["index.html"]["content"]
            content_type = self.loaded_files["index.html"]["content_type"]
            self.send_response(content,content_type)
        else:
            self.send_error()
#HANDLES CSS PATH
    def css_path(self, request, handler):
        if "style.css" in self.loaded_files:
            content = self.loaded_files["style.css"]["content"]
            content_type = self.loaded_files["style.css"]["content_type"]
            self.send_response(content, content_type)
        else:
            self.send_error()
#HANDLES JS PATH
    def js_path(self, request, handler):
        if "webrtc.js" in self.loaded_files:
            content = self.loaded_files["webrtc.js"]["content"]
            content_type = self.loaded_files["webrtc.js"]["content_type"]
            self.send_response(content, content_type)
        else:
            self.send_error()

#HANDLES IMAGE PATH
    def image_path(self, request, handler):
        image_name = f"/image/{request.path.split('/')[-1]}"
        if image_name in self.loaded_files:
            content = self.loaded_files[image_name]["content"]
            content_type = self.loaded_files[image_name]["content_type"]
            self.send_response(content, content_type)
        else:
            self.send_error()

#SENDS RESPONSE TO CLIENT(BROWSER)
    def send_response(self, content, content_type):
        if isinstance(content, str):
            content = content.encode()
        header = (f"HTTP/1.1 200 OK\n"
                      f"Content-Type: {content_type}\n"
                      f"Content-Length: {len(content)}\n"
                      "X-Content-Type-Options: nosniff\n"
                      "\n")
        self.request.sendall(header.encode() + content)
#SENDS ERROR TO CLIENT(BROWSER)
    def send_error(self):
        message="404 Not Found"
        content=message.encode()
        content_len=len(content)
        header=("HTTP/1.1 404 Not Found\n"
                "Content-Type: text/plain\n"
                f"Content-Length: {content_len}\n"
                "X-Content-Type-Options: nosniff\n"
                "\n")
        self.request.sendall(header.encode()+b"404 Not Found")


def main():
    host = "0.0.0.0"
    port = 8080
    socketserver.TCPServer.allow_reuse_address = True

    server = socketserver.TCPServer((host, port), MyTCPHandler)

    print("Listening on port " + str(port))
    server.serve_forever()


if __name__ == "__main__":
    main()
