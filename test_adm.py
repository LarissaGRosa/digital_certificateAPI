import json
import requests

URL = 'http://localhost:8080/api'


print('TESTE 1 - CRIAR ADMINISTRADOR')
#create new normal user
headers1 = { 'content-type': 'application/json'}
body_data = {"username":"lari1_adm","email":"teste@teste4.com", "password":"fmse2001", "role":["user","admin"]}

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
body_data = {"username":"lari1_adm", "password":"fmse2001"}

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

print('TESTE 3 - CRIAR AUTORIDADE CERTIFICADORA')
#create AC
headers1 = { "content-type": "application/json",
              "Authorization": "Bearer "+ token }
body_data = {"cn":"ac teste 2", "ou":"aa", "o":"AAA", "l":"AAAA", "st":"AAAA", "c":"BBB", "ui":"KKKKKK"}

try:
    req1 = requests.post(
        url=URL + '/adm/new_ac',
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

print('TESTE 4 - ATIVAR AUTORIDADE CERTIFICADORA')
#activate ac
headers1 = { 'content-type': 'application/json',
'Authorization': "Bearer "+ token
}
body_data = {"ac_id":"12"}

try:
    req1 = requests.put(
        url=URL + '/adm/a_ac',
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

print('TESTE 5 - DESATIVAR AUTORIDADE CERTIFICADORA')
#deactivate ac
headers1 = { 'content-type': 'application/json',
'Authorization': "Bearer "+ token
}
body_data = {"ac_id":"3"}

try:
    req1 = requests.put(
        url=URL + '/adm/d_ac',
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

print('TESTE 6 - LISTAR AUTORIDADE CERTIFICADORA')
#list acs
headers1 = { 'content-type': 'application/json',
'Authorization': "Bearer "+ token
}

try:
    req1 = requests.get(
        url=URL + '/adm/all_acs',
        headers=headers1, timeout=10
        )
    req1.raise_for_status()
except requests.exceptions.HTTPError as err:
    print('HTTPError: %s.' % err)

# extracting response text
userdata = req1.text
print(userdata)

print('_____________________________________________________')

print('TESTE 7 - LIBERAR CERTIFICADO')
#activate ac
headers1 = { 'content-type': 'application/json',
'Authorization': "Bearer "+ token
}
body_data = {"dc_id":"17"}

try:
    req1 = requests.put(
        url=URL + '/user/a_dc',
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

print('TESTE 8 - BLOQUEAR CERTIFICADO')
#deactivate ac
headers1 = { 'content-type': 'application/json',
'Authorization': "Bearer "+ token
}
body_data = {"dc_id":"12"}

try:
    req1 = requests.put(
        url=URL + '/user/d_dc',
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

print('FIM TESTES api/adm && api/auth')