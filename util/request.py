class Request:
    def __init__(self, request: bytes):
        self.method = ""
        self.path = ""
        self.http_version = ""
        self.headers = {}
        self.cookies = {}
        self.body = b""

        header_end = request.find(b'\r\n\r\n')
        if header_end == -1:
            return

        header_bytes = request[:header_end]
        body_bytes = request[header_end + 4:]  # Skip over the '\r\n\r\n'

        header_str = header_bytes.decode("utf-8")
        header_lines = header_str.split('\r\n')

        if len(header_lines) == 0 or header_lines[0].strip() == "":
            return

        request_line = header_lines[0].split(' ')
        if len(request_line) < 3:
            return

        self.method = request_line[0]
        self.path = request_line[1]
        self.http_version = request_line[2]

        # Parse headers
        for line in header_lines[1:]:
            if ': ' in line:
                key, value = line.split(': ', 1)
                self.headers[key.strip()] = value.strip()

        # Parse cookies if any
        if 'Cookie' in self.headers:
            cookie_header = self.headers['Cookie']
            cookies = cookie_header.split(';')
            for cookie in cookies:
                if '=' in cookie:
                    key, value = cookie.split('=', 1)
                    self.cookies[key.strip()] = value.strip()

        # Set the body (keep it as bytes)
        self.body = body_bytes
