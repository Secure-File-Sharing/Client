FROM python:3.7

RUN mkdir -p /home/security
WORKDIR /home/security

COPY requirements.txt ./

RUN pip3 install -r requirements.txt

COPY CryptographyModule.py ./
COPY client.py ./

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

RUN apt-get update && apt-get install iputils-ping

CMD ping 127.0.0.1
