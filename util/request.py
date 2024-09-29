class Request:

    def __init__(self, request: bytes):
        self.method = ""
        self.path = ""
        self.http_version = ""
        self.headers = {}
        self.cookies = {}
        self.body = b""

        request_str = request.decode('utf-8')
        lines = request_str.split('\r\n')

        requestline=lines[0].split(' ')
        if len(requestline) != 3:
            print("ERROR SEE BELOW")
            print(requestline)
            raise ValueError('Invalid request line')
        self.method = requestline[0]
        self.path = requestline[1]
        self.http_version = requestline[2]
        self.body = lines[-1].encode('utf-8')



        for line in lines[1:-1]:
            if line:
                key, value = line.split(': ')
                self.headers[key.strip()] = value.strip()
        if 'Cookie' in self.headers:
            cookie_header = self.headers['Cookie']
            cookies = cookie_header.split(';')
            for cookie in cookies:
                key, value = cookie.split('=', 1)
                self.cookies[key.strip()] = value.strip()


def test1():
    request = Request(b'GET / HTTP/1.1\r\nHost: localhost:8080\r\nConnection: keep-alive\r\n\r\nhello')
    assert request.method == "GET"
    assert "Host" in request.headers
    assert request.headers["Host"] == "localhost:8080"  # note: The leading space in the header value must be removed
    assert request.body == b'hello'


    # There is no body for this request.
    # When parsing POST requests, the body must be in bytes, not str

    # This is the start of a simple way (ie. no external libraries) to test your code.
    # It's recommended that you complete this test and add others, including at least one
    # test using a POST request. Also, ensure that the types of all values are correct


if __name__ == '__main__':
    test1()
