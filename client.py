import requests
from CryptographyModule import CryptoCipher
import binascii
import os
from time import sleep
import json
import random
import sys

URL = "http://127.0.0.1:8000"
MAX_FILE_SIZE = 10**6

SERVER_PUBLIC_KEY = 65537
P_SERVER = (
    "00b0bd0679a743d362eeaa68d6dacf"
    "065657d26d170208139c3f486dd11e"
    "facf0219c21c80cc55ed11b9e5874a"
    "c95d46de13e4f2b9f69d033fb2edce"
    "10e6d4209c0c11f6f4ed0de7e8a2d4"
    "0e66eeafe7743b5507bd2e1571f744"
    "cda42cb7647dd1d90bb0c92c3b9665"
    "16b968439eb4659944477daa2ce8c6"
    "479544f9a5fce7e4628126b41b99ee"
    "e93f92928d267fa541924f7278ce95"
    "709387915a7b2a64317e1bd61b36dd"
    "556cd3c2fbc5f2f61455b58abfd1c9"
    "3587e18124c0b63779a296b96757b5"
    "43530a6aba0c9b67b461ee834a3974"
    "dd7d52c1f3f0b0d9bf81e26a6f615d"
    "51c51308adfcbb310bfe26faa2254e"
    "4f61b7e41a88b99b5efe913624fe3f"
    "a16b"
)

P = ("00C890F33B82D6284AA2D4282AE6B85365583D5CBEC790FACB09B71DBA645A5E803F73C7CF4B722E232E16A0842C3FBBB605D7A75F050044CAC5157BB4FB4ADD44BA0048FBA331A332010C4596DBBB803AB7DA4BBBF4EAEB67190417FE881E31C8323FBEE9BB6B60FB0E07E314C1AA637D4D3372DD6D4C08BB80B94FCD6FE683A609BE49FDA9058461AD1521B917585465FDC1C2B6A47C57375CF5CA0F2B26C60B01F5EF50B1463B83BCA5F9FEB995820DCCAC61CA08C777E8E8080AA1CF82161790001E65166E8289E1590ECB116E94F861897E588F9DE7BD9E95671E7FFB0ACDA106309EDDEF05D3742C1DE15EE641DBA5C7B16118C6B388D0040CCD4E457C87"
)


PUBLIC_KEY = 65537

PRIVATE_KEY = (
    "7A9515043F6012BA2330D5E7FAA197DEEE027B07E34339F5145805E460E756B0BD974EFCE458C1D8209815BD12AA5558D7D349696ACE123D781D3C418E00E0A1DBA8C6F27D789E0CB6D5404706BF5F8D03C778D844C5BBE0844A9B3BA70805571D5716A1163A77C89977BA937A1660BE398C035D502AD37F7E1A44AB0404785AD1376E4D99B7203008959A8D91EB581B1D39EC3760317D1CB31CC530F3B35E99FB9B6B103265A90DF3FFC213ADA8FB46F6459D844E53824058042CC2529FE07C138277BBCD59DA01BCD21DC7AB3C575B4A43A1C13A12FBBEA1100FD5C7D71D18E5F6F606C00999F39A477FB498CC9B78D00E5D16713FFDBB74B72FC178529BA9"
)


def register(obj, params={}, headers={}):
    string = "{}".format(params)
    data = {
        "data": obj.encrypt_text(string)
    }
    try:
        x = requests.post(
            url=URL+"/register/",
            data=data, 
            headers=headers
        )
        if x.status_code == 201 or x.status_code == 400:
            responde = x.json()['response']
            dec_responde = obj.decrypt_text(responde).replace('\'', '\"')
            msg = json.loads(dec_responde)['response']
            print(msg)
        else:
            print("Invalid request for register")
    except Exception as e:
        print("Register request failed.")
        print(e.__class__.__name__)
        sleep(5)


def login (obj, params={}, headers={}):
    string = "{}".format(params)
    data = {
        "data": obj.encrypt_text(string)
    }
    try:
        x = requests.post(
            url=URL+"/login/",
            data=data, 
            headers=headers
        )
        if x.status_code == 200:
            responde = x.json()['response']
            dec_responde = obj.decrypt_text(responde).replace('\'', '\"')
            token = json.loads(dec_responde)['token']
            print("You have successfully logged in")
            return token
        elif x.status_code == 401 or x.status_code == 400:
            print("Login Failed. Check your credentials")
            return ""
        else:
            print("Invalid request")
            return ""
    except Exception as e:
        print("Login request failed.")
        print(e.__class__.__name__)
        sleep(5)


def list_items(obj, headers):
    try:
        x = requests.post(
            url=URL+"/list/",
            headers=headers
        )
        if x.status_code == 200:
            responde = x.json()['response']
            responde = obj.decrypt_text(responde)
            responde = json.loads(responde)
            print("----------------------------------------------------------------------------")
            print("File Name", '\t|', "owner", '\t\t|', "conf. label", '\t|', "integrity label")
            for item in responde:
                print(
                    item['file_name'], '\t\t|', 
                    item['owner'], '\t\t|', 
                    item['confidentiality_label'], '\t\t|', 
                    item['integrity_label']
                )
            print("----------------------------------------------------------------------------")
        elif x.status_code == 401:
            print("Please login")
    except Exception as e:
        print("list request failed.")
        print(e.__class__.__name__)


def upload(obj, params, headers):
    try:
        string = "{}".format(params)
        data = {
            "data": obj.encrypt_text(string)
        }
        x = requests.put(
            url=URL+"/upload/",
            data=data,
            headers=headers
        )
        if x.status_code == 201:
            print("File uploaded successfully")
        elif x.status_code == 401:
            print("Please login")
        elif x.status_code == 400:
            print("Upload failed. The reason could be for that file name exist")
    except Exception as e:
        print("Upload failed")
        print(e.__class__.__name__)


def read_file(obj, params, headers):
    try:
        string = "{}".format(params)
        data = {
            "data": obj.encrypt_text(string)
        }
        x = requests.post(
            url=URL+"/read/",
            data=data,
            headers=headers
        )
        if x.status_code == 200:
            responde = x.json()['response']
            responde = obj.decrypt_text(responde).replace('\'', '\"')
            print(responde)
        elif x.status_code == 401:
            print("Please login")
        elif x.status_code == 403:
            print("Access Denied")
        elif x.status_code == 503:
            print("File does not exist")
    except Exception as e:
        print("read failed.")
        print(e.__class__.__name__)


def write_file(obj, params, headers):
    try:
        string = "{}".format(params)
        data = {
            "data": obj.encrypt_text(string)
        }
        x = requests.post(
            url=URL+"/write/",
            data=data,
            headers=headers
        )
        if x.status_code == 200:
            responde = x.json()['response']
            responde = obj.decrypt_text(responde).replace('\'', '\"')
            print(responde)
        elif x.status_code == 401:
            print("Please login")
        elif x.status_code == 403:
            print("Access Denied")
        elif x.status_code == 503:
            print("File does not exist")
    except Exception as e:
        print("Write failed")
        print(e.__class__.__name__)


def get(obj, params, headers):
    try:
        string = "{}".format(params)
        data = {
            "data": obj.encrypt_text(string)
        }
        x = requests.post(
            url=URL+"/get/",
            data=data,
            headers=headers
        )
        if x.status_code == 200:
            responde = x.json()['response']
            responde = obj.decrypt_text(responde).replace('\'', '\"')
            responde = json.loads(responde)
            with open("./"+responde['file_name'], 'w') as f:
                f.write(responde['data_file'])
        elif x.status_code == 401:
            print("Please login")
        elif x.status_code == 403:
            print("Access Denied")
        elif x.status_code == 503:
            print("File does not exist")

    except Exception as e:
        print("Get failed")
        print(e.__class__.__name__)


def entrance_menu():
    print("<Usage>: ")
    print("\t> register <username> <password> <conf. label> <integrity label>") 
    print("\t> login <username> <password>")
    print("\t> clear")
    print("\t> quit")

def main_menu():
    print("<Usage>: ")
    print("\t> put <filename> <conf.label> <integrity label>")
    print("\t> read <filename>")
    print("\t> write <filename> <content>")
    print("\t> get <filename>")
    print("\t> ls")
    print("\t> clear")
    print("\t> quit")

def clear_screen():
    if os.name == 'nt':
        _ = os.system('cls')
    else:
        _ = os.system('clear')


if __name__ == "__main__":
    print("Welcome")
    session_key = int(binascii.hexlify(os.urandom(128)), base=16)
    enc_ses = str(pow(session_key, SERVER_PUBLIC_KEY, int(P_SERVER, 16)))
    cipher = CryptoCipher(str(session_key))
    Token = ""
    while True:
        while True:
            entrance_menu()
            command = input("~$ ")
            command = command.split()
            if len(command) == 0:
                continue
            if command[0] == "register":
                if len(command) == 5:
                    parameters= {
                        "username": command[1],
                        "password": command[2],
                        "confidentiality_label": command[3],
                        "integrity_label": command[4]
                    }
                    headers = {
                        "Session-Key": enc_ses
                    }
                    register(obj=cipher, params=parameters, headers=headers)
                else:
                    print("Invalid command.")
                    print("<Usage>: register <username> <password> <conf. label> <integrity label>")
            elif command[0] == "login":
                if len(command) == 3:
                    parameters= {
                        "username": command[1],
                        "password": command[2]
                    }
                    headers = {
                        "Session-Key": enc_ses
                    }
                    Token = login(obj=cipher, params=parameters, headers=headers)
                    if Token:
                        break
                else:
                    print("Invalid command.")
                    print("<Usage>: login <username> <password>")
            elif command[0] == "clear":
                clear_screen()
            elif command[0] == "quit":
                print("Bye!")
                sys.exit()
                break
            else:
                print("please use mentioned command!!!")
            print('\n')
        print('\n')
        while True:
            main_menu()
            command = input("~$ ")
            command = command.split()
            if len(command) == 0:
                continue
            if command[0] == "put":
                if len(command) == 4:
                    try:
                        if(os.stat(command[1]).st_size <= (MAX_FILE_SIZE)):
                            file_obj = open(command[1], 'r').read()
                            data = {
                                "file_name": command[1],
                                "data_file": file_obj,
                                "confidentiality_label": command[2],
                                "integrity_label": command[3]
                            }
                            headers = {
                                "Session-Key": enc_ses,
                                "Authorization": "Token " + Token
                            }
                            upload(obj=cipher, params=data, headers=headers)
                        else:
                            print("File limit size exceeded")
                    except (OSError, FileNotFoundError) as e:
                        print(e)
                else:
                    print("Invalid command.")
                    print("<Usage>: put <filename> <conf.label> <integrity label>")
            elif command[0] == "read":
                if len(command) == 2:
                    try:
                        data = {
                            "file_name": command[1]
                        }
                        headers = {
                            "Session-Key": enc_ses,
                            "Authorization": "Token " + Token
                        }
                        read_file(obj=cipher, params=data, headers=headers)
                    except Exception as e:
                        print(e)
                else:
                    print("Invalid command.")
                    print("<Usage>: read <filename>")
            elif command[0] == "write":
                if len(command) >= 3:
                    content = ' '.join([str(element) for element in command[2:]])
                    if(len(content) <= (MAX_FILE_SIZE)):
                        try:
                            data = {
                                "file_name": command[1],
                                "content": content
                            }
                            headers = {
                                "Session-Key": enc_ses,
                                "Authorization": "Token " + Token
                            }
                            write_file(obj=cipher, params=data, headers=headers)
                        except OSError as e:
                            print(e)
                    else:
                        print("File limit size exceeded")
                else:
                    print("Invalid command.")
                    print("<Usage>: write <filename> <content>")
            elif command[0] == "get":
                print("get")
                if len(command) == 2:
                    try:
                        data = {
                            "file_name": command[1]
                        }
                        headers = {
                            "Session-Key": enc_ses,
                            "Authorization": "Token " + Token
                        }
                        get(obj=cipher, params=data, headers=headers)
                    except OSError as e:
                        print(e)
                else:
                    print("Invalid command.")
                    print("<Usage>: get <filename>")
            elif command[0] == "ls":
                if len(command) == 1:
                    headers = {
                        "Session-Key": enc_ses,
                        "Authorization": "Token " + Token
                    }
                    list_items(obj=cipher, headers=headers)
                else:
                    print("Invalid command.")
                    print("<Usage>: ls")
            elif command[0] == "clear":
                clear_screen()
            elif command[0] == "quit":
                print("Bye!")
                sys.exit()
                break
            else:
                print("please use mentioned command!!!")
        
            print('\n')
