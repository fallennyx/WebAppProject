FROM python:3

ENV HOME /root
WORKDIR /root

COPY . .

RUN apt-get update && \
    apt-get install -y libmagic1 && \
    rm -rf /var/lib/apt/lists/*

RUN pip3 install -r requirements.txt

EXPOSE 8080

ADD https://github.com/ufoscout/docker-compose-wait/releases/download/2.2.1/wait /wait
RUN chmod +x /wait

CMD /wait && python3 -u server.py
