#Libraries we will use
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto import Random
from base64 import b64encode, b64decode
import hashlib
import random

#Diffie - Hellman's key exchange protocol
class DH(object):
    def __init__(self, public_key, private_key, prime):
        self.public_key = public_key
        self.private_key = private_key
        self.prime = prime
        self.full_key = None

    def generate_partial_key(self):
        partial_key = self.public_key**self.private_key 
        partial_key = partial_key%self.prime
        return partial_key

    def generate_full_key(self, partial_key_r):
        full_key = partial_key_r**self.private_key
        full_key = full_key%self.prime
        self.full_key = full_key
        return full_key
      
 #AES algorithm for encryption
class AESCipher(object):
    def __init__(self, key):
        self.block_size = AES.block_size
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, plain_text):
        plain_text = self.__pad(plain_text)
        iv = Random.new().read(self.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        encrypted_text = cipher.encrypt(plain_text.encode())
        return b64encode(iv + encrypted_text).decode("utf-8")

    def decrypt(self, encrypted_text):
        encrypted_text = b64decode(encrypted_text)
        iv = encrypted_text[:self.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        plain_text = cipher.decrypt(encrypted_text[self.block_size:]).decode("utf-8")
        return self.__unpad(plain_text)

    def __pad(self, plain_text):
        number_of_bytes_to_pad = self.block_size - len(plain_text) % self.block_size
        ascii_string = chr(number_of_bytes_to_pad)
        padding_str = number_of_bytes_to_pad * ascii_string
        padded_plain_text = plain_text + padding_str
        return padded_plain_text

    @staticmethod
    def __unpad(plain_text):
        last_character = plain_text[len(plain_text) - 1:]
        return plain_text[:-ord(last_character)]
      
  
  ########## Diffie - Hellman's key exchange protocol ##########

#In this stage both Alice and Bob choose the same public keys
#and they both pick a private key which is not shared.

set_random_seed(12345)

##### Process to produce a public generator of  Zp#####

#Initializing starting parametrs
def generate_parameters(bits):
    # choose two primes such that p=2q+1
    p=1
    while not is_prime(p):
        q = next_prime(ZZ.random_element(2^bits))
        p = 2*q + 1
    
    F = GF(p)
    Zp = IntegerModRing(p)

    # find a primitive element g that has order 
    g = F(2)
    if multiplicative_order(Zp(g)) != (p-1):
        g = F(Mod(-2, p))

    return p, q, g, F

#We choose 512 bits in order to fast our computation. Identically we should choose 1024 or more bits
#for maximum security
p, q, g, F = generate_parameters(512) 
print ("The public parameter prime p is: ", p)
print ("The public parameter AB_pub is: ", g )

#The public parameters are the following
AB_pub = g 
prime = p

#The private parameters should be between 2, 3, ..., p-2
A_pr = random_prime(p-2) 
B_pr = random_prime(p-2)

##### Diffie - Hellman's key exchange protocol #####

#Alice for Diffie - Hellman
Alice = DH(AB_pub, A_pr, prime)

#Bob for Diffie - Hellman
Bob = DH(AB_pub, B_pr, prime)

#Alice generates partial key to send it to Bob into an insecure channel
y_A=Alice.generate_partial_key()
print("Alice's partial public key is: ", y_A)

#Bob generates partial key to send it to Alice into an insecure channel
y_B=Bob.generate_partial_key()
print("Bob's partial public key is: ", y_B)

#Alice uses Bob's partial key to generate the key that will be used to encrypt 
#the message she wants to encrypt with AES encryption
key_AES1=Alice.generate_full_key(y_B)
print("Alice's final key is: ", key_AES1)

#Bob uses Alice partial key to generate the key that will be used to decrypt the message 
#from Alice which is encrypted with AES encryption
key_AES2=Bob.generate_full_key(y_A)
print("Bob's final key is: ", key_AES2)

#checking that both Alice and Bob final keys is the same in order to use them in AES encryption
if (key_AES1 == key_AES2):
    print("The keys are the same. The encryption key for AES is: ", key_AES1)

#No we can use either alice_final_key or bob_final_key for AES encryption, since they are the same 


########## Man In The Middle Attack ##########

#In this case, the private keys A_pr and B_pr for Alice and Bob respectively are the same. The public parameters AB_pub and prime p
#are also the same

set_random_seed(12345)

#Eve generates to primes in order to use them for Alice and Bob
Eve_key1 = random_prime(p-2) #key for attack to Alice
Eve_key2 = random_prime(p-2) #key for attack to Bob

#The communication is not between Alice and Bob. It has been seperated in 2 parts

##### 1st part #####

#Communication between Eve and Alice
#Eve blocks y_B from reaching Alice
#Instead, she sends z_B to Alice using her private key Eve_key1
fake_Bob = DH(AB_pub, Eve_key1, prime)
z_B=fake_Bob.generate_partial_key()
print("Bob's fake partial key is: ", z_B)
#Alice computes the fake key_A using Bob's fake partial key
alice_fake_key=Alice.generate_full_key(z_B)
print("Alice's fake key is: ",alice_fake_key)

##### 2nd part #####

#Communication between Eve and Bob
#Eve blocks y_A from reaching Bob
#Instead, she sends z_A to Bob using her private key
fake_Alice = DH(AB_pub, Eve_key2, prime)
z_A=fake_Alice.generate_partial_key()
print("Alice's fake partial key is: ", z_A)
#Bob computes the fake key_B using Alice's fake partial key
bob_fake_key=Bob.generate_full_key(z_A)
print("Bob's fake key is: ",bob_fake_key)

##### Eve can also calculate the fake keys #####
eve_key_alice = fake_Bob.generate_full_key(y_A)
print("Eve's key for communication with Alice is: ", eve_key_alice)
eve_key_bob = fake_Alice.generate_full_key(y_B)
print("Eve's key for communication with Bob is: ", eve_key_bob)


########## Example without HMAC authentication ##########

#Converting fake keys to string in order to pass them into the AES algoritmh
eve_key_alice = str(eve_key_alice)
eve_key_bob = str(eve_key_bob)

#Alice uses her fake key to encrypt the message she wants to send to Bob
key_AES_Alice = AESCipher(eve_key_alice) 
encrypted_message_from_alice_to_bob = key_AES_Alice.encrypt("Bob, you must transfer 1000 euros to me to the following bank account number 3676564783")
print("The encrypted message is: ", encrypted_message_from_alice_to_bob)

#Now Eve decrypt this message using the key which has previously produced 
decrypted_message_from_alice_to_bob = key_AES_Alice.decrypt(encrypted_message_from_alice_to_bob)
print("The original decrypted message is: ", decrypted_message_from_alice_to_bob)

#Eve chooses to alter the original message before delivering it to Bob
#What it does is convert 1000 euros to 10,000 euros and uses its own bank account in place of Alice's
#For the encryption she will use the produced key between her and Bob. 
key_AES_Bob = AESCipher(eve_key_bob) 
encrypted_message_from_eve_to_bob = key_AES_Bob.encrypt("Bob, you must transfer 10000 euros to me to the following bank account number 6547865674")

#Bob delivers the encrypted message from Eve and decrypts it
decrypted_message_from_eve_to_bob = key_AES_Bob.decrypt(encrypted_message_from_eve_to_bob)
print("The fake decrypted message is: ", decrypted_message_from_eve_to_bob)



########### Authenticate Diffie-Hellman's producted key with ##########
########## HMAC authentication to avoid Man in The Middle Attack ##########

set_random_seed(12345)

#Defining the secret key provided by a trusted authentication center
prime_HMAC = random_prime(p)
print("The secret key for HMAC authentication is: ", prime_HMAC)
#The secret key in bytes for HMAC algorithm is
secret = b"{prime_HMAC}"

#Alice produces the HMAC of partial key using their secret key provided from a trusted
#authentication center and sends it along with 
#the partial key, which then will be blocked from Eve
h_A = HMAC.new(secret)
#the following key is y_A
h_A.update(b"{y_A}") 
print ("Partial's key HMAC is: ", h_A.hexdigest())

#Bob then recieves the partial key and the HMAC supposing that it comes from Alice. To check this he uses HMAC
#to check the authenticity of the message. However, instead of y_A he posseses z_A. If Eve blocks MAC 
#from reaching Bob, he is sure that something is going wrong, because he expects it.
h_B = HMAC.new(secret)
#this key is z_A
h_B.update(b"{z_A}") 
print ("Partial's key HMAC is: ", h_B.hexdigest())

#Bob checks the two MACs to check if Alice is the original sender and if the message has been altered
if (h_A.hexdigest() == h_B.hexdigest()):
    print("The message is authentic and has not been modified. You can use tha partial key to produce the key of AES")
    
else:
    print("The message is not authentic and has been modified. Don't use the partial key. You have to produce AES key with a safer way.")
    
    
    
########## AES authenticated encryption ##########

#Alice wants to sent a message to Bob
#She uses key_AES supposing that they have ensured that this key is authentic using HMAC authentication

#Converting key to string in order to pass it into the AES algoritmh
key_AES1 = str(key_AES1)

#Asking Alice to enter the key of the AES algorithm (the key is alice_final_key)
AES_process = AESCipher(key_AES1)

#ask Alice to enter the message which will be encrypted and sent to Bob
text_for_encryption = AES_process.encrypt("Bob, you must transfer 1000 euros to me to the following account number 3676564783")
print("The encrypted message is: ", text_for_encryption, " and will be sent to Bob")


########### Authenticate AES cipher text with ##########
########## HMAC authentication ##########

#The secret HMAC key is the same 

#Alice produces the HMAC of encrypted message
h_A2 = HMAC.new(secret)
h_A2.update(b"{text_for_encryption}") 
print ("Encrypted message's MAC is: ", h_A2.hexdigest())

#Bob then recieves the encrypted message and its MAC. To check its auntheticity he generates the MAC
#of the encrypted message 
h_B2 = HMAC.new(secret)
h_B2.update(b"{text_for_encryption}") 
print ("Encrypted message's MAC is: ", h_B2.hexdigest())

#He checks if the two MACs are the same
if (h_A2.hexdigest() == h_B2.hexdigest()):
    print("The message is authentic and has not been modified")
    
else:
    print("The message is not authentic and has been modified. Stop communication ")
    
    
########## AES decryption ##########

#After authentication, Bob wants to decrypt the received encrypted message
#He uses key_AES 

#Bob uses the key of the AES algorithm
AES_process_Bob = AESCipher(key_AES1)

#Bob decrypts the message
text_for_decryption = AES_process_Bob.decrypt(text_for_encryption)
print("The decrypted message is: ", text_for_decryption)
