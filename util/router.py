class Router:
    def __init__(self):
        self.routes=[]
    def add_route(self, method, path, action, exact_path=False):
        self.routes.append({
            'method': method,
            'path': path,
            'handler': action,
            'exact_match': exact_path
        })
    def route_request(self, request, handler):
        for route in self.routes:
            if route['method'] == request.method:
                if route['exact_match'] and route['path'] == request.path:
                    route['handler'](request, handler)
                    return
                elif route['exact_match']==False and request.path.startswith(route['path']):
                    route['handler'](request, handler)
                    return

        self.send_404_response(handler)

    def send_404_response(self, handler):
        response ='HTTP/1.1 404 Not Found\r\n'
        response +='Content-Type: text/plain\r\n'
        response +='Content-Length: 13\r\n'
        response +='\r\n'
        response +='404 Not Found'
        handler.request.sendall(response.encode())


                





