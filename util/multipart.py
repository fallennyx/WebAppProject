from util.request import Request

class ParsedMultipart:
    def __init__(self, boundary, parts):
        self.boundary = boundary
        self.parts = parts  # List of Part objects

class Part:
    def __init__(self, headers, name, content):
        self.headers = headers  # Dictionary of headers
        self.name = name        # Name from Content-Disposition header
        self.content = content  # Content as raw bytes

def parse_multipart(request):
    content_type = request.headers.get('Content-Type', '')
    boundary_marker = 'boundary='
    boundary = content_type.split(boundary_marker)[1] if boundary_marker in content_type else None
    if not boundary:
        return ParsedMultipart(boundary="", parts=[])

    delimiter = f'--{boundary}'.encode()
    parts = request.body.split(delimiter)
    parsed_parts = []

    for part in parts:
        part = part.strip()
        if not part or part == b'--':
            continue
        if part.startswith(b'\r\n'):
            part = part.lstrip(b'\r\n')
        if part.endswith(b'--'):
            part = part.rstrip(b'--').strip()

        try:
            # Split headers from content by the first occurrence of b"\r\n\r\n"
            header_section, content = part.split(b'\r\n\r\n', 1)
        except ValueError:
            print("Error during multipart")
            continue

        # Process headers
        headers = {}
        header_lines = header_section.split(b'\r\n')
        for line in header_lines:
            try:
                line_str = line.decode('utf-8')
                if ": " in line_str:
                    key, value = line_str.split(": ", 1)
                    headers[key.strip()] = value.strip()
            except UnicodeDecodeError:
                continue

        # Extract name from Content-Disposition header
        disposition = headers.get("Content-Disposition", "")
        disposition_params = {}
        if disposition:
            parts_disp = disposition.split(';')
            for disp_part in parts_disp[1:]:
                if '=' in disp_part:
                    key, value = disp_part.strip().split('=', 1)
                    disposition_params[key.strip()] = value.strip().strip('"')

        name = disposition_params.get("name")
        if not name:
            continue

        # Create a Part object with headers, name, and raw content (no decoding)
        part_obj = Part(headers=headers, name=name, content=content.rstrip(b'\r\n'))
        parsed_parts.append(part_obj)

    # Return ParsedMultipart object with boundary and parts list
    return ParsedMultipart(boundary=boundary, parts=parsed_parts)


received_data = b"""POST /upload HTTP/1.1\r
Host: localhost\r
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW\r
Content-Length: 357\r
\r
------WebKitFormBoundary7MA4YWxkTrZu0gW\r
Content-Disposition: form-data; name="username"\r
\r
john_doe\r
------WebKitFormBoundary7MA4YWxkTrZu0gW\r
Content-Disposition: form-data; name="file"; filename="example.jpg"\r
Content-Type: image/jpeg\r
\r
(binary data for the image file goes here)\r
------WebKitFormBoundary7MA4YWxkTrZu0gW--\r
"""
mpr=(parse_multipart(Request(received_data)))
print(mpr.parts[1].name)



