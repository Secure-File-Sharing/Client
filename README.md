# Client
This is the client code for communicating to [server](https://github.com/Secure-File-Sharing/Back-end). You can find more info about the APIs there.

## Requirements 
* python3.7

## RUN
To run the project we can directly run this script:
```
python client.py
```
or simply use docker:
```
sudo docker build -t client .
sudo docker run -it client bash
```

When using docker, remember to replace *URL* variable in client.py as follow:

```python
URL = "127.0.0.1:8000" --> URL = "http://YOUR.INTERFACE.IP"
```

In the shell opened by docker container:
```
python3 client.py
```


