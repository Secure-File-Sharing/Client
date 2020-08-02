import requests
from CryptographyModule import CryptoCipher
from Crypto.PublicKey import RSA
import binascii
import os
from time import sleep
import json
import random

URL = "http://127.0.0.1:8000"

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


def register (obj, api, params={}, headers={}):
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
        if x.status_code == 200:
            responde = x.json()['response']
            dec_responde = obj.decrypt_text(responde).replace('\'', '\"')
            token = json.loads(dec_responde)['token']
            return token
        else:
            return ""
    except Exception as e:
        print("Register request failed.")
        print(e)
        sleep(5)


def login (obj, api, params={}, headers={}):
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
        elif x.status_code == 401:
            print("Login Failed. Check your credentials")
            return ""
    except Exception as e:
        print("Login request failed.")
        print(e)
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
        print(e)


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
        if x.status_code == 200:
            print("File uploaded successfully")
        elif x.status_code == 401:
            print("Please login")
        elif x.status_code == 400:
            print("Upload failed")
    except Exception as e:
        print("Upload failed")
        print(e)


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
        print(e)


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
        print(e)


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
        if x.status_code == 200
            responde = x.json()['response']
            responde = obj.decrypt_text(responde).replace('\'', '\"')
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
        print(e)


def menu():
    print("<Usage>: ")
    print("\t1. register <username> <password> <conf. label> <integrity label>") 
    print("\t2. login <username> <password>")
    print("\t3. put <filename> <conf.label> <integrity label>")
    print("\t4. read <filename>")
    print("\t5. write <filename> <content>")
    print("\t6. get <filename>")
    print("\t7. ls")
    print("\t8. clear")
    print("\t7. quit")


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
        menu()
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
                responde = register(obj=cipher, api="/register/", params=parameters, headers=headers)
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
                Token = login(obj=cipher, api="/login/", params=parameters, headers=headers)
            else:
                print("Invalid command.")
                print("<Usage>: login <username> <password>")
        elif command[0] == "put":
            print("put")
            if len(command) == 4:
                try:
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
                except OSError as e:
                    print(e)
            else:
                print("Invalid command.")
                print("<Usage>: put <filename> <conf.label> <integrity label>")
        elif command[0] == "read":
            print("read")
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
            print("write")
            if len(command) > 3:
                try:
                    data = {
                        "file_name": command[1],
                        "content": ' '.join([str(element) for element in command[2:]])
                    }
                    headers = {
                        "Session-Key": enc_ses,
                        "Authorization": "Token " + Token
                    }
                    write_file(obj=cipher, params=data, headers=headers)
                except OSError as e:
                    print(e)
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
            break
        else:
            print("please use mentioned command!!!")
        
        print('\n')


        
# a = 29452672612284248168818412010345342359134808271745217500412735942217766002721937379889547220471641515978743925894495553685274780070399532482178097397514213422283213748783223243338988423160375598778073547836562316296494404370780153339463605364284211222423282479020058893030617529242498184419381811285056377466406651618549376180904424381176690318881005345565687340682208324424876688831492204420662319990190312006038169961593492569428051298268267879358867298646849286687320279956957065193319688360178814536153754200577256311812177988762621979819403582865807204925637996021706643092846786278628348611534829059815782527610

# b = 19705634124968120680132955111683984390675562976411408822756317143848385472941370768314475284344631549697531883693921590796712601089167389040689297058064148133920497917768058876857719348448395878231776612568755719953051587820679920213101284640134078143686391141327617442727670451014666115505864389107424671565317919019541166022472039743059745753523928394055194669055749252041746895658520283380345276828034418643005292761610784381840822113366916105759525553874152588217107801859400191070133611347847952330443427666513292977281069983007137838949268371904476973474285818782353755399556120278227467680092394297615409150617
# c = 14713428274055530947803198510047505619792302752079605590068575745089073799363343763306362481731320818613373659083243595284061227716172465627889339175521635248489461325681793101973129442046870176214406605546111315155049640139578462590312378690632207659834153834250054967442406887015763796079131608479652849533779889313493323568766326115190502385944687402329319186708832570632480308565591016874972830676767227958136031927422196840508663959841304928769646417903278617343916117781540788025872547166720677061309600496935024351120691309882385160606849452172931251445352020314568008747356042998659099380795894109849720458494
# d = 29010925180193083260401644745127290287748634700779097089081604557352554910571279251046102767586818913094258763228067727422250392158777232146767368678501016608817666206484058444470826202206887999256685719880899092148602301585680866582206290909693752735335961770101453280286062339357494454174685130638487844848455472384543736405896579990778890015258933521664470854217822415147592527610977748077410101808585234606395436586031369973057952926661294124870743381789692384016838226953355368334331135723940494000611208676150386581895380860807687761170822811331845443898210673122858219821211535587327334478884843606338128968729

# okay_e = 22142643045989486106361339040031001428018207546920148224074665369308799738990638543070067162140079080096012969842246796567767663352546900940259105672371025605933404714936010682111735090614562863385768218841570207814239645886006817003379340636385078528783192744641555533683311104246152530253878673214907502395088456862589964658164576048427084921141540050101583894035639322982345549015923771498855038330438649587798094080800805941324005344917014719006528974990673379483219752499142903919038781081068025743310396869855533760242035056322845127113600257991586366625272757404109385047769794731037116158663683833881116819114
# f = 14886811025718307634209481407414983180384816349511167435379146182869582499780417968933891540848350767323641554138263847636657716047671853286171196381855432614532671370305589530094009542783917307992808396467494614524737597877416686340713319581569310444943523859733307267581547445067728295796248352663844168147817234130710499506926104328789525759139757792550489035847246908835715903754408253374201822821193054240957208222343932983439157332984898153181990667615289166532075154962310834657044517646091287276812419437600319852925165394121706067528076585819316114141347870525795423463644494838229938368164715222796581311341
# g = 30028543287804799479772194297110318128490491043754187384017780377362277325001535920381384236341160899918427811286413654532713901430200368383750097091648193502294112111821513707991781347658067510800238448993929402105527505603380572909134343414658412746733820211320881361145686146253529643490994360212012545421400131369506552026268783252379327907174045138588422512260018894451674914109191157135209760666426484496012528636519920815700669347266526852995990394871343187362174826948415526260203244257880623582973745495335020740005774865844275068980564376975702646942913613501434858325342047649858442669762172264568297112161
# h = 29745469814433642020518471444408650085975914635904440458145734567032207472306203268195384504881885731157683192853353676963044873243081391462400004425471057137463050077601369528482824260436015287554262927218022640450776986055235407458712215246774029071102171255783080068997641643479864646711587489853465818243875391535047833447162833134645836210322775082469807997568069089094453106521708005505657555147491872301914693694418154498661566336368147527286933370139233271749287557599163548274457552332933867597848965908540150485904455743969872949073769566786084883494191579825239907343181683038893890794418811212242972739743
# i = 29085471674470453304152029113595725079488219982774547275466216147401306414341173066018928748938623048149348951730384212717117890816816272964679091740524198593711753009988536876231874932648484383006276357358388396186996789703882419718372245415863996093316975280103137788048653980030438893680792834674326272496753688231862776419674774945689458505995735942496078832856382957922706024043816164536738316080324045832965664078658488760606427038960963796267635637965785649201120156350015061292459829945897600780469038163990425983420244090491266241506320222975876551453402732750484883728128375038503566182094510091453668242359
# pkay_k = 10694015353576769240626915628068366529583822257764759541438606359562523276874957601173291882472424619499816984209826740050869235147371453436146812934545476096695269470025092598896062891569567406403374071408117711413399483714176046456834194366144083117196215686612575624682610311184665725005928242722103495553615784352431137691118681722807677828010341052176192070538444612551921221548495429922937401737579352326892786945353151870884465406888006696002784045752249746872859986208706063072342815926279158552030287704781156794077928751328607369909120193544126238748296266691789135068806338668265142141984360416002467913786

# okay_l = 323300483375935300162666843873783061135217099427943058346825841740035016146614852261218029424919539973849058431605020935138023131620901413222327880470011211045723629467055119650197418956282784468587540791338908780974599206505321722328711099775900158301327890043612928807282277514381837922647343294027956223162837344886878886187012295326568193832810017478068128137777343668244457087304171184178153485105634613455230238272299864696798436421940941632232791808630860743086686161182462541772681941508552317278803186564669742267891986921757318622419006252502624521784795190222596951316100666890008793612195171715396443786
# # session_key = 22142643045989486106361339040031001428018207546920148224074665369308799738990638543070067162140079080096012969842246796567767663352546900940259105672371025605933404714936010682111735090614562863385768218841570207814239645886006817003379340636385078528783192744641555533683311104246152530253878673214907502395088456862589964658164576048427084921141540050101583894035639322982345549015923771498855038330438649587798094080800805941324005344917014719006528974990673379483219752499142903919038781081068025743310396869855533760242035056322845127113600257991586366625272757404109385047769794731037116158663683833881116819114


# m = 22938629004280356287148401286809441079791161862579953175630279918822506999593039889755414625740244096421309528299015063886200870423220953263270628857135706360082776852094359142111656815171866439735661113644019908392655650983380612412743624996707359469519179761745219696265398770439198547089066273002057093748955858179355572272722482657124697808731616046613811975178053863122885628015899467220883786820420024219023493216808391965035773122874974860314472318696617284271482791148538292171257220996409640760691258702545340070686007216262223234463715642300790042564929707534577363103789426695438473708471632928732876375024
