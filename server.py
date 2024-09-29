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
        self.router.add_route("GET", "/public/style.css", self.css_path, True)
        self.router.add_route("GET", "/public/webrtc.js", self.js_path, True)
        self.router.add_route("GET", "/public/functions.js", self.js_path, True)
        self.router.add_route("GET", "/public/image/", self.image_path, False)
        self.router.add_route("GET", "/public/favicon.ico", self.icon_path, True)

        self.visits = 1

        self.files = {
        "public/index.html": "text/html",
        "public/style.css": "text/css",
        "public/webrtc.js": "application/javascript",
        "public/functions.js": "application/javascript",
        "public/image/elephant.jpg": "image/jpeg",
        "public/image/flamingo.jpg": "image/jpeg",
        "public/image/kitten.jpg": "image/jpeg",
        "public/image/cat.jpg": "image/jpeg",
        "public/image/dog.jpg": "image/jpeg",
        "public/image/eagle.jpg": "image/jpeg",
        "public/image/elephant-small.jpg": "image/jpeg",
        "public/favicon.ico": "image/x-icon",
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
        request = Request(received_data)
        self.router.route_request(request, self)
        print(f"Request path from Handle sent to route_request: {request.path}")


    #LOADS FILES INTO DICTIONARY
    #OPENS FILES IN READ BINARY MODE
    #READS CONTENT OF FILE
    #STORES CONTENT OF FILE IN DICTIONARY
    def load_files(self):
        for filename, content_type in self.files.items():
            file_path = filename
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
        #UPDATES COOKIES
        if "public/index.html" in self.loaded_files:
            #Cookies
            if "visits" in request.cookies:
                self.visits = int(request.cookies["visits"]) + 1

            content = self.loaded_files["public/index.html"]["content"]
            content_type = self.loaded_files["public/index.html"]["content_type"]
            content = content.replace(b'{{visits}}', str(self.visits).encode())
            self.send_response(content, content_type, True)

        else:
            self.send_error()

    #HANDLES CSS PATH
    def css_path(self, request, handler):
        if "public/style.css" in self.loaded_files:
            print("CSS PATHJIGGYYYYHERE")
            content = self.loaded_files["public/style.css"]["content"]
            content_type = self.loaded_files["public/style.css"]["content_type"]
            print(content_type)
            self.send_response(content, content_type)
        else:
            self.send_error()

    #HANDLES JS PATH
    def js_path(self, request, handler):
        if request.path =="/public/webrtc.js" and request.path[1:] in self.loaded_files:
            content = self.loaded_files["public/webrtc.js"]["content"]
            content_type = self.loaded_files["public/webrtc.js"]["content_type"]
            self.send_response(content, content_type)
        elif request.path =="/public/functions.js" and request.path[1:] in self.loaded_files:
            content = self.loaded_files["public/functions.js"]["content"]
            content_type = self.loaded_files["public/functions.js"]["content_type"]
            self.send_response(content, content_type)
        else:
            self.send_error()

    #HANDLES IMAGE PATH
    def image_path(self, request, handler):
        image=request.path[1:]
        if image in self.loaded_files:
            content = self.loaded_files[image]["content"]
            content_type = self.loaded_files[image]["content_type"]
            self.send_response(content, content_type)
        else:
            self.send_error()

    def icon_path(self, request, handler):
        if "public/favicon.ico" in self.loaded_files:
            content = self.loaded_files["public/favicon.ico"]["content"]
            content_type = self.loaded_files["public/favicon.ico"]["content_type"]
            self.send_response(content, content_type)
        else:
            self.send_error()

    #SENDS RESPONSE TO CLIENT(BROWSER)
    def send_response(self, content, content_type,set_cookie=False):
        header = (f"HTTP/1.1 200 OK\r\n"
                  f"Content-Type: {content_type};charset=utf-8\r\n"
                  f"Content-Length: {len(content)}\r\n"
                  "X-Content-Type-Options: nosniff\r\n")
        if set_cookie:
            header +=(f"Set-Cookie: visits={self.visits};Max-Age=3600;Path=/\r\n\r\n")
        else:
            header += "\r\n"
        self.request.sendall(header.encode() + content)



    #SENDS ERROR TO CLIENT(BROWSER)
    def send_error(self):
        message = "404 Not Found"
        content = message.encode()
        content_len = len(content)
        header = ("HTTP/1.1 404 Not Found\n"
                  "Content-Type: text/plain\n"
                  f"Content-Length: {content_len}\n"
                  "X-Content-Type-Options: nosniff\n"
                  "\n")
        self.request.sendall(header.encode() + b"404 Content Not Found")


def main():
    host = "0.0.0.0"
    port = 8080
    socketserver.TCPServer.allow_reuse_address = True

    server = socketserver.TCPServer((host, port), MyTCPHandler)

    print("Listening on port " + str(port))
    server.serve_forever()


if __name__ == "__main__":
    main()
