import requests
from requests.exceptions import RequestException
import time
import json
from functools import lru_cache

RATE_LIMIT_DELAY = 1.5

@lru_cache(maxsize=100)
def get_location(ip: str) -> dict:
    """
    Get geolocation information for a given IP address.

    Args:
        ip (str): The IP address or hostname to get geolocation information for.

    Returns:
        dict: A dictionary containing the geolocation information for the given IP address or host.
    """
    time.sleep(RATE_LIMIT_DELAY)

    try:
        url = f"http://ip-api.com/json/{ip}"
        response = requests.get(url, timeout=5)
        values = response.json()
    except RequestException:
        return {"error": "API not available", "timestamp": time.time()}

    return values

if __name__ == '__main__':

    ip = input("What is your target IP: ")
    values = get_location(ip)

    print("IP: " + values["query"])
    print("City: " + values["city"])
    print("ISP: " + values["isp"])
    print("Country: " + values["country"])
    print("Region: " + values["region"])
    print("Timezone: " + values["timezone"])
