import hashlib
import uuid

import bcrypt
from bson import ObjectId

from util.auth import extract_credentials, validate_password
from util.request import Request
from util.router import Router
from pymongo import MongoClient
import json
import html
import socketserver
from util.multipart import parse_multipart
import os
import magic

mongo_client = MongoClient("mongo")
db = mongo_client["cse312"]
chat_collection =db["chat"]
users = db["users"]
mime=magic.Magic(mime=True)
os.makedirs('public/media-uploads', exist_ok=True)
class MyTCPHandler(socketserver.BaseRequestHandler):


    # Initializes Router object, adds routes to Router object,
    def __init__(self, request, client_address, server):
        self.router = Router()
        os.makedirs('public/media-uploads', exist_ok=True)




        # Define routes
        self.router.add_route("GET", "/", self.index_path, True)
        self.router.add_route("GET", "/public/style.css", self.css_path, True)
        self.router.add_route("GET", "/public/webrtc.js", self.js_path, True)
        self.router.add_route("GET", "/public/functions.js", self.js_path, True)
        self.router.add_route("GET", "/public/image/", self.image_path, False)
        self.router.add_route("GET", "/public/favicon.ico", self.icon_path, True)
        self.router.add_route("POST", "/chat-messages", self.post_chat_message, True)
        self.router.add_route("GET", "/chat-messages", self.get_chat_messages, True)
        self.router.add_route("DELETE", "/chat-messages/", self.delete_chat_message, False)
        self.router.add_route("POST", "/register", self.register, True)
        self.router.add_route("POST", "/login", self.login, True)
        self.router.add_route("POST", "/logout", self.logout, True)
        self.router.add_route("POST", "/media-uploads", self.upload_media, False)
        self.router.add_route("GET", "/public/media-uploads/", self.media_uploads_path, False)

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
        self.visits = 1
        super().__init__(request, client_address, server)

    def handle(self):
        try:
            received_data = b""
            while True:
                chunk = self.request.recv(2048)
                if not chunk:
                    break
                received_data += chunk

                while b'\r\n\r\n' in received_data:
                    # Split headers and remaining data
                    headers, remaining_data = received_data.split(b'\r\n\r\n', 1)

                    # Parse Content-Length
                    header_lines = headers.split(b'\r\n')
                    content_length = 0
                    for line in header_lines:
                        if line.lower().startswith(b"content-length"):
                            content_length = int(line.split(b":")[1].strip())
                            break

                    # Check if the body is fully received
                    if len(remaining_data) < content_length:
                        break  # Wait for more data

                    # Extract the current request's body
                    body = remaining_data[:content_length]
                    extra_data = remaining_data[content_length:]  # Buffer extra data

                    # Process the current request
                    request = Request(headers + b'\r\n\r\n' + body)
                    self.router.route_request(request, self)

                    # Prepare for the next request
                    received_data = extra_data

        except Exception as e:
            print(f"Error in handle method: {e}")
            self.send_302_found()

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

    # Handles index path
    def index_path(self, request, handler):
        if "public/index.html" in self.loaded_files:
            content = self.loaded_files["public/index.html"]["content"]
        else:
            print("indexfilenotfound")
            self.send404error()
            return

        if "visits" in request.cookies:
            self.visits = int(request.cookies["visits"]) + 1
            content = content.replace(b'{{visits}}', str(self.visits).encode())
        else:
            content = content.replace(b'{{visits}}', str(self.visits).encode())

        xsrf_token = None
        if "auth_token" in request.cookies:
            user = users.find_one({"auth_token": request.cookies["auth_token"]}, {"username": 1, "_id": 0})
            if user:
                xsrf_token = user.get("xsrf_token", None)
                if xsrf_token is None:
                    print("generating new token")
                    xsrf_token = str(uuid.uuid4())
                    users.update_one({"auth_token": request.cookies["auth_token"]}, {"$set": {"xsrf_token": xsrf_token}})
                    print("token generated and added to db")
                content = content.replace(
                    b'{{auth_section}}',
                    b'<form action="/logout" method="post"><input type="submit" value="Logout"></form>'
                )
            else:
                content = content.replace(
                    b'{{auth_section}}',
                    b'''
                    Register:
                    <form action="/register" method="post" enctype="application/x-www-form-urlencoded">
                        <label>Username: <input type="text" name="username"/></label>
                        <br/>
                        <label>Password: <input type="password" name="password"></label>
                        <input type="submit" value="Post">
                    </form>

                    Login:
                    <form action="/login" method="post" enctype="application/x-www-form-urlencoded">
                        <label>Username: <input type="text" name="username"/></label>
                        <br/>
                        <label>Password: <input type="password" name="password"></label>
                        <input type="submit" value="Post">
                    </form>
                    '''
                )
        else:
            content = content.replace(
                b'{{auth_section}}',
                b'''
                Register:
                <form action="/register" method="post" enctype="application/x-www-form-urlencoded">
                    <label>Username: <input type="text" name="username"/></label>
                    <br/>
                    <label>Password: <input type="password" name="password"></label>
                    <input type="submit" value="Post">
                </form>

                Login:
                <form action="/login" method="post" enctype="application/x-www-form-urlencoded">
                    <label>Username: <input type="text" name="username"/></label>
                    <br/>
                    <label>Password: <input type="password" name="password"></label>
                    <input type="submit" value="Post">
                </form>
                '''
            )
        if xsrf_token:
            content = content.replace(b'{{xsrf_token}}', xsrf_token.encode())
        else:
            content = content.replace(b'{{xsrf_token}}', b'')
        self.send_response(content, "text/html", 200, visits=self.visits)

    # Handles CSS path
    def css_path(self, request, handler):
        if "public/style.css" in self.loaded_files:
            content = self.loaded_files["public/style.css"]["content"]
            content_type = self.loaded_files["public/style.css"]["content_type"]
            print(content_type)
            self.send_response(content, content_type)
        else:
            self.send404error()

    # Handles JS path
    def js_path(self, request, handler):
        if request.path == "/public/webrtc.js" and request.path[1:] in self.loaded_files:
            content = self.loaded_files["public/webrtc.js"]["content"]
            content_type = self.loaded_files["public/webrtc.js"]["content_type"]
            self.send_response(content, content_type)
        elif request.path == "/public/functions.js" and request.path[1:] in self.loaded_files:
            content = self.loaded_files["public/functions.js"]["content"]
            content_type = self.loaded_files["public/functions.js"]["content_type"]
            self.send_response(content, content_type)
        else:
            self.send404error()

    # Handles image path
    def image_path(self, request, handler):
        image = request.path.lstrip('/')
        if image in self.loaded_files:
            content = self.loaded_files[image]["content"]
            content_type = self.loaded_files[image]["content_type"]
            self.send_response(content, content_type)
        else:
            self.send404error()

    def icon_path(self, request, handler):
        if "public/favicon.ico" in self.loaded_files:
            content = self.loaded_files["public/favicon.ico"]["content"]
            content_type = self.loaded_files["public/favicon.ico"]["content_type"]
            self.send_response(content, content_type)
        else:
            self.send404error()


    def send_response(self, content, content_type, status_code=200, visits=None, auth_token=None):
        header = (f"HTTP/1.1 {status_code} OK\r\n"
                  f"Content-Type: {content_type}; charset=utf-8\r\n"
                  f"Content-Length: {len(content)}\r\n"
                  "X-Content-Type-Options: nosniff\r\n")
        if auth_token:
            header += (f"Set-Cookie: auth_token={auth_token}; HttpOnly; Max-Age=3600; Path=/\r\n")
        if visits:
            header += (f"Set-Cookie: visits={visits}; Max-Age=3600; Path=/\r\n")
        header += "\r\n"
        self.request.sendall(header.encode() + content)

    # Handles user registration
    def register(self, request, handler):
        try:
            data = extract_credentials(request)
            print("data good")
            if data is None:
                print("Data is None")
                return self.send_302_found()
            username = data[0]
            password = data[1]
            print("username and password good")
            if not validate_password(password):
                print("Password not valid")
                return self.send_302_found()
            password = data[1].encode('utf-8')
            hashedPass = bcrypt.hashpw(password, bcrypt.gensalt())
            print("hashed password good")
            db.users.insert_one({"username": username, "password": hashedPass})
            self.send_302_found()
        except Exception as e:
            print(f"Error in register, from register function: {e}")
            self.send_302_found()

    # Handles user login
    def login(self, request, handler):
        try:
            data = extract_credentials(request)
            username = data[0]
            password = data[1].encode('utf-8')
            user = db.users.find_one({"username": username})
            if user:
                hashed = user["password"]
                if bcrypt.checkpw(password, hashed):
                    token = str(uuid.uuid4()).encode()
                    hash_object = hashlib.sha256()
                    hash_object.update(token)
                    hashedToken = hash_object.hexdigest()
                    db.users.update_one({"username": username}, {"$set": {"auth_token": hashedToken}}, upsert=True)
                    self.visits = 0
                    self.send_302_found(visits=self.visits, auth_token=hashedToken)
                else:
                    print("password not good")
                    self.send_302_found()
            else:
                print("user not good")
                self.send_302_found()
        except Exception as e:
            print(f"Error in login: {e}")
            self.send_302_found()

    # Handles posting chat messages
    def post_chat_message(self, request, handler):
        try:
            data = json.loads(request.body.decode('utf-8'))
            user = "Guest"
            message = data['message']
            if request.cookies.get("auth_token") is not None and request.cookies.get("auth_token") != "expired":
                auth = request.cookies.get("auth_token")
                username = users.find_one({"auth_token": auth}, {"username": 1, "_id": 0})
                xsrf = users.find_one({"auth_token": auth}, {"xsrf_token": 1, "_id": 0})
                if username:
                    if data["xsrf_token"] != xsrf["xsrf_token"]:
                        print("XSRF token not valid")
                        self.send403error()
                        return
                    result = chat_collection.insert_one({"username": username["username"], "message": message})
                    response = json.dumps({"message_id": str(result.inserted_id)})
                    self.send_response(response.encode('utf-8'), 'application/json')
                    return
                else:
                    print("User not found")
            else:
                print("No auth token")
            result = chat_collection.insert_one({"username": user, "message": message})
            response = json.dumps({"message_id": str(result.inserted_id)})
            self.send_response(response.encode('utf-8'), 'application/json')

        except Exception as e:
            print(f"Error in post_chat_message: {e}")
            self.send404error()

    # Handles retrieving chat messages
    def get_chat_messages(self, request, handler):
        try:
            messages = list(chat_collection.find())
            formatted_messages = []
            for msg in messages:
                message_content = msg['message']
                if message_content.strip().startswith('<img') or message_content.strip().startswith('<video'):
                    formatted_message = message_content  # Render as-is
                else:
                    formatted_message = html.escape(message_content)
                    print("escaped")
                formatted_messages.append({
                    "username": msg['username'],
                    "message": formatted_message,
                    "id": str(msg['_id'])
                })
            response = json.dumps(formatted_messages)
            self.send_response(response.encode('utf-8'), 'application/json')
        except Exception as e:
            print(f"Error in get_chat_messages: {e}")
            self.send404error()

    def delete_chat_message(self, request, handler):
        try:

            message_id = request.path.split('/')[-1]
            auth_token = request.cookies.get("auth_token")
            if not auth_token:
                if chat_collection.find_one({"_id": ObjectId(message_id)})["username"]=="Guest" :
                    result = chat_collection.delete_one({"_id": ObjectId(message_id)})
                    self.send_response(b'', 'application/json', 204)
                    return
                else:
                    print("No auth token")
                    self.send_302_found()
                    return

            user = users.find_one({"auth_token": auth_token}, {"username": 1, "_id": 0})
            if not user:
                print("User not found")
                self.send_302_found(visits=request.cookies.get("visits"))
                return

            message = chat_collection.find_one({"_id": ObjectId(message_id)})
            if not message:
                print("Message not found")
                self.send403error()
                return
            if message["username"] != user["username"]:
                print("User not authorized to delete message")
                self.send403error()
                return

            result = chat_collection.delete_one({"_id": ObjectId(message_id)})
            self.send_response(b'', 'application/json', 204)
        except Exception as e:
            print(f"Error in delete_chat_message: {e}")
            self.send404error()

    # Handles user logout
    def logout(self, request, handler):
        try:
            if "auth_token" in request.cookies:
                db.users.update_one(
                    {"auth_token": request.cookies.get("auth_token")},{"$unset": {"auth_token": ""}})
                self.send_302_found(auth_token="expired")
            else:
                print("No auth token")
                self.send404error()
        except Exception as e:
            print(f"Error in logout: {e}")
            self.send404error()

    def send404error(self):
        message = "404 Not Found"
        content = message.encode()
        content_len = len(content)
        header = ("HTTP/1.1 404 Not Found\n"
                  "Content-Type: text/plain\n"
                  f"Content-Length: {content_len}\n"
                  "X-Content-Type-Options: nosniff\n"
                  "\n")
        self.request.sendall(header.encode() + content)

    #  403 error
    def send403error(self):
        message = "403 Forbidden"
        content = message.encode()
        content_len = len(content)
        header = ("HTTP/1.1 403 Forbidden\n"
                  "Content-Type: text/plain\n"
                  f"Content-Length: {content_len}\n"
                  "X-Content-Type-Options: nosniff\n"
                  "\n")
        self.request.sendall(header.encode() + b"403 Forbidden")

    # Sends 302 Found redirect
    def send_302_found(self, visits=None, auth_token=None,content=None):
        if content:
            content_type=mime.from_buffer(content)
        else:
            content_type="text/html"
            content=b" "

        header = (f"HTTP/1.1 302 Found\r\n"
                  "Location: /\r\n"
                  f"Content-Type:{content_type}; charset=utf-8\r\n"
                  f"Content-Length: {len(content)}\r\n"
                  "X-Content-Type-Options: nosniff\r\n")
        if visits:
            header += (f"Set-Cookie: visits={visits}; Max-Age=3600; Path=/\r\n")
            if auth_token == "expired":
                header += "Set-Cookie: auth_token=; HttpOnly; Max-Age=0; Path=/\r\n"
        if auth_token:
                header += f"Set-Cookie: auth_token={auth_token}; HttpOnly; Max-Age=3600; Path=/\r\n"
        header += "\r\n"
        self.request.sendall(header.encode() + content)

    def upload_media(self, request, handler):
        try:
            # Step 1: Parse the multipart body
            multipart = parse_multipart(request)
            if multipart is None:
                print("Failed to parse multipart data")
                return self.send_302_found()

            for part in multipart.parts:
                if part.name.lower() == "upload":
                    file_content = part.content
                    break
            file_type=mime.from_buffer(file_content)
            print(file_type)
            unique_id = uuid.uuid4().hex
            ex=file_type.split("/")[1]
            filename = f"file_{unique_id}.{ex}"

            upload_dir = "public/media-uploads"
            file_path = os.path.join(upload_dir, filename)

            with open(file_path, "wb") as f:
                f.write(file_content)
            print(f"File saved to {file_path}")
            username = "Guest"
            if request.cookies.get("auth_token"):
                user = users.find_one(
                    {"auth_token": request.cookies.get("auth_token")}, {"username": 1, "_id": 0}
                )
                if user:
                    username = user["username"]

            relative_path = f"/public/media-uploads/{filename}"
            if ex in ['jpg', 'png', 'gif',"jpeg"]:
                message = f'<img src="{relative_path}" alt="Uploaded Image"/>'
            elif ex == 'mp4':
                message = f'''
                <video controls autoplay muted>
                 <source src={relative_path} type="video/mp4">
                 Your browser does not support video playback
                </video>
                '''

            chat_collection.insert_one({"username": username, "message": message})
            self.send_302_found(content=file_content)

        except Exception as e:
            print(f"Error during media upload: {e}")
            self.send_302_found()


    def media_uploads_path(self, request, handler):
        file_path = request.path.lstrip('/')
        safe_path = os.path.normpath(file_path)
        if not safe_path.startswith("public/media-uploads/"):
            print("Attempted directory traversal attack")
            return self.send404error()
        try:
            with open(file_path, "rb") as f:
                content = f.read()
                file_type = mime.from_buffer(content)
            self.send_response(content, file_type)
        except FileNotFoundError:
            print("File not found:", file_path)
            self.send404error()
        except Exception as e:
            print(f"Error serving media file {file_path}: {e}")
            self.send404error()


def main():
    host = "0.0.0.0"
    port = 8080
    socketserver.TCPServer.allow_reuse_address = True

    server = socketserver.ThreadingTCPServer((host, port), MyTCPHandler)
    print("Listening on port " + str(port))
    server.serve_forever()


if __name__ == "__main__":
    main()
