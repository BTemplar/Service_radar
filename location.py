import urllib.request as urllib2
import json

def get_location(ip):
    url = "http://ip-api.com/json/"
    response = urllib2.urlopen(url + ip)
    data = response.read()
    values = json.loads(data)

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
