import urllib.request
import json

try:
    url2 = "http://localhost:8000/stats/summary"
    req = urllib.request.Request(url2)
    with urllib.request.urlopen(req) as response:
        data = json.loads(response.read().decode())
        print("Summary:", data)
except Exception as e:
    print("Error:", e)
