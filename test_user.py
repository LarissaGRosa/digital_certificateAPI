import json
import requests

URL = 'http://localhost:8080/api'


print('TESTE 1 - CRIAR NORMAL USER')
#create new normal user
headers1 = { 'content-type': 'application/json'}
body_data = {"username":"lari_10","email":"teste10@teste.com", "password":"fmse2001", "role":["user"]}

try:
    req1 = requests.post(
        url=URL + '/auth/signup',
        data=json.dumps(body_data),
        headers=headers1, timeout=10
        )
    req1.raise_for_status()
except requests.exceptions.HTTPError as err:
    print('HTTPError: %s.' % err)

# extracting response text
userdata = req1.text
print(userdata)

print('_____________________________________________________')
#login
print('TESTE 2 - ENTRAR NO SISTEMA')
headers1 = { 'content-type': 'application/json'}
body_data = {"username":"lari_10", "password":"fmse2001"}

try:
    req1 = requests.post(
        url=URL + '/auth/signin',
        data=json.dumps(body_data),
        headers=headers1, timeout=10
        )
    req1.raise_for_status()
except requests.exceptions.HTTPError as err:
    print('HTTPError: %s.' % err)

# extracting response text
userdata = req1.text
print(userdata)
print('_____________________________________________________')
token = str((json.loads(userdata))['accessToken'])

print('TESTE 3 - CRIAR CERTIFICADO DIGITAL')

headers1 = { "content-type": "application/json",
              "Authorization": "Bearer "+ token }
body_data = {"cn":"meu certificado teste 2", "ou":"aa", "o":"AAA", "l":"AAAA", "st":"AAAA", "c":"BBB", "ui":"KKKKKK",
             "auth_id":"12"}

try:
    req1 = requests.post(
        url=URL + '/user/new_dc',
        data=json.dumps(body_data),
        headers=headers1, timeout=10
        )
    req1.raise_for_status()
except requests.exceptions.HTTPError as err:
    print('HTTPError: %s.' % err)

# extracting response text
userdata = req1.text
print(userdata)


print('_____________________________________________________')

print('TESTE 4 - LISTAR MEUS CERTIFICADOS')
#list acs
headers1 = { 'content-type': 'application/json',
'Authorization': "Bearer "+ token
}

try:
    req1 = requests.get(
        url=URL + '/user/my_dcs',
        headers=headers1, timeout=10
        )
    req1.raise_for_status()
except requests.exceptions.HTTPError as err:
    print('HTTPError: %s.' % err)

# extracting response text
userdata = req1.text
print(userdata)

print('_____________________________________________________')

print('TESTE 5 - BAIXAR CERTIFICADO')
#list acs
headers1 = {
'Authorization': "Bearer "+ token
}

try:
    req1 = requests.post(
        url=URL + '/user/download',
        data = "meu certificado teste 2",
        headers=headers1, timeout=10
        )
    req1.raise_for_status()
except requests.exceptions.HTTPError as err:
    print('HTTPError: %s.' % err)

# extracting response text
userdata = req1.text
print(userdata)

print('_____________________________________________________')

print('FIM TESTES api/adm && api/auth')