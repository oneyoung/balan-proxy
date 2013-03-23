## Introduction
This is a Socks5 proxy written in python and forked from balan-proxy project.

## Features
1. Use gevent instead of Threading Server.
2. Support multiple servers, you can easily add them in config file.
3. support simple encrypt, to avoid being blocked by GFW.
4. merge both local and server in only one file.

## Usage
### Server
The way to start a server:
```bash
python proxy.py -s PORT KEY
```
For example, the below will setup a socks5 server, that listen to port 6789, and use encrypt key "foobar!".
```bash
python proxy.py -s 6789 foobar!
```

### Local
#### config file
The local proxy service depends on a config file to determine:
1. which port to listen
2. how many servers can connect to

The config file typically looks like below.
1. `local` section is required, and need to specify `listen_port`
2. More than one proxy sever is allowed.
```
[local]
# requred
listen_port=8888

[proxy1]
host=your-proxy1.com
port=1234
key=foobar!

[proxy2]
host=your-proxy2.com
port=2345
```

#### run a local server.
Syntax:
```bash
python proxy.py [-c config]
```
Defalt the script will take "config.ini" as the default config file.
But you can use another file with `-c` option.

#### use the proxy.
1. make sure the proxy type is `socks5`
2. point proxy server to `127.0.0.1` and port as `LISTEN_PORT` (the value of `listen_port`)
