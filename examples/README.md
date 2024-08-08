# Exemples

## exploit.py
Basic exemple file where you need to replace the leak function based on your needs.

## Challenge
The challenge contain a single Dockerfile with 2 apps :
 * NodeJS app containing path traversal
 * Flask app in debug mode

The purpose of the challenge is to demonstrate the flexibility of the library even if the leak is not on the same app (but still on the same machine).
### Build
```bash
docker build -t challenge:1.0.0 .
```

### Run
```bash
docker run --rm  -p 3000:3000 -p 5000:5000 challenge:1.0.0
```

### Solve
Import requirements :

```bash
pip3 install requests beautifulsoup4 wconsole-extractor
```

Run the writeup :
```bash
python3 writeup.py
```

Check that the pin match the one displayed when the docker container is started.