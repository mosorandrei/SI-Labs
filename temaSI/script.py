from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.strxor import strxor
import copy

def xor_bytes(a, b):
    """ Returns a new byte array with the elements xor'ed. """
    return bytes([i^j for i, j in zip(a, b)])

class KeyManager:
    def __init__(self,K_P):
        self.K_P = K_P                       #publica, accesibila tuturor
        self.__K=get_random_bytes(16)        #privata, doar nodul va sti de ea

    def getK(self): # only for testing
        return self.__K

    def encryptedKeyForNodeA(self):            #functie de a trimite cheia criptata de aes catre A
        K = self.__K
        cipher = AES.new(self.K_P, AES.MODE_ECB)
        return cipher.encrypt(K)


class NodeA:
    def __init__(self,K_P,criptedkey,IV):
        with open('../fisier.txt') as f:
            self.__message = f.read()     #mesajul privat de trimis , accesat doar de el
        self.K_P=K_P;                           # cheia publica
        self.__criptedkey=criptedkey            # cheia criptata obtinuta de la KeyManager
        decipher = AES.new(K_P, AES.MODE_ECB)
        self.__K=decipher.decrypt(criptedkey)   #decriptarea cheii cu aes
        self.IV=IV

    def encryptedKeyForNodeB(self):             # trimiterea cheii catre b
        return self.__criptedkey

    def getK(self): # only for testing
        return self.__K

    def getMessage(self):
        return self.__message #onlyfortesting



    def encryptMessage(self,mode):
        if mode == "CFB":
            result = b''
            message=self.__message.encode('utf-8')
            plaintext = [message[i:i + 16] for i in range(0, len(message), 16)]
            save = copy.deepcopy(self.IV)
            cipher = AES.new(self.__K, AES.MODE_CFB, save)
            for block in plaintext:
                encrypted_IV = cipher.encrypt(save)
                save = xor_bytes(block, encrypted_IV)
                result += save

            return result
        else:
            result = b''
            plaintext = [self.__message[i:i + 16] for i in range(0, len(self.__message), 16)]
            cipher = AES.new(self.__K, AES.MODE_ECB)
            for block in plaintext:
                result += cipher.encrypt(block.encode('utf-8'))
            return result


class NodeB:
    def __init__(self,K_P,criptedkey,IV):
        self.K_P=K_P;                                            #cheia publica
        self.__criptedkey=criptedkey                             #cheia criptata de la B
        decipher = AES.new(K_P, AES.MODE_ECB)
        self.__K=decipher.decrypt(criptedkey)
        self.IV=IV                                               #decriptarea

    def canWeCommunicate(self):
        if(self.__K is None):                                    #daca am ajuns in acest punct inseamna ca putem
            return False                                         #continua cu transmiterea mesajului
        return True

    def getK(self): # only for testing
        return self.__K


    def DecryptMessage(self,mode,encryptedmessage):
        if mode == "CFB":
            result = b''
            plaintext = [encryptedmessage[i:i + 16] for i in range(0, len(encryptedmessage), 16)]
            save = copy.deepcopy(self.IV)
            cipher = AES.new(self.__K, AES.MODE_CFB, save)
            for block in plaintext:
                decrypted_IV =xor_bytes(block, cipher.encrypt(save))
                save = block
                result += decrypted_IV

            return result
        else:
            result = b''
            plaintext = [encryptedmessage[i:i + 16] for i in range(0, len(encryptedmessage), 16)]
            cipher = AES.new(self.__K, AES.MODE_ECB)
            for block in plaintext:
                result += cipher.decrypt(block)

            return result




#incepem sa modelam scenariul , facand abstractie de protocol , am incercat sa modelez scenariul folosind functii si variabile private , in detrimentul unui protocol tcp , de pilda
cheie=get_random_bytes(16)                                      # cheia K' comuna
IV=get_random_bytes(16)
KM = KeyManager(cheie)                               # nodul KeyManager
A = NodeA(cheie,KM.encryptedKeyForNodeA(),IV)           # nodulA
B = NodeB(cheie,A.encryptedKeyForNodeB(),IV)            # nodulB
if(B.canWeCommunicate()):                             # daca cei doi pot comunica , inseamna ca au obtinut aceeasi cheie
        print('-----------ECB RESULT--------------')
        print(B.DecryptMessage('ECB',A.encryptMessage('ECB')).decode('utf-8'))   #print(A.getK()==B.getK())  va da true
        print('-----------CFB RESULT------------')
        print(B.DecryptMessage('CFB', A.encryptMessage('CFB')).decode('utf-8'))  # print(A.getK()==B.getK())  va da true