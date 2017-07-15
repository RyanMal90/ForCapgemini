import sys
import os, random
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import pickle
import getpass
import hashlib
#clears terminal, welcomes users and prommpts to make enter password, if no password go to menu.
def main():
    os.system("clear")
    print "Welcome to this password wallet."
    if os.path.isfile(".hash.txt"):
        with open('.hash.txt') as fp:
            hash_val = fp.readline().rstrip("\n")
        print "Please enter your master password!"
        password = getpass.getpass('Password:')
        password_hash = hashlib.sha256(password).hexdigest()
        if password_hash == hash_val:
            print password
            print getKey(password)
            print getKey(str(password))
            decrypt(getKey(str(password)), "(encrypted).output.txt")
            menu()
        else:
           print "Invalid Password, Please try again!"
           main()
    else:
       menu()

#Allows users to select an option, the option slected will run the module that corresponds to that number
def menu():
    os.system("clear")
    mode = raw_input("""Please select from one of the following options:\n
                (1). Create new service entry
                (2). View specific entry
                (3). View all entries
                (4). Service Delete
                (5). Quit\n""")
    if mode == '1':
        mode2 = raw_input("Would you like to add multiple services?: Y/N?")
        if mode2 == 'Y' or mode2 == 'y':
            createMultiple()
        elif mode2 == 'N' or mode2 == 'n':
            createEntry()
            menu()
        else:
            print "Y or N only, not case sensitive."
            menu()
    elif mode == '2':
        serviceDisplay()
    elif mode =='3':
        displayAll()
    elif mode =='4':
        serviceEdit()
    elif mode =='5':
        exitProgram()
    else:
        print "Invalid selection! Please select between one of the 6 options available."
        menu()
#Using the pickle module the state of the users entries is saved. allowing multiple entries.
def createMultiple():
    os.system("clear")
    Credentials = {}
    x = 0
    while x != 1:
        Services = []
        Service = raw_input('Please enter the service:'   )
        Services.append(raw_input('Please Enter your Username:' ))
        Services.append(raw_input('Please Enter your Password:' ))
        Credentials[Service] = Services
        output = open(".output.txt", "ab+")
        #saves user state of file containing login details for services.
        pickle.dump(Credentials, output)
        selection = raw_input("Would you like to enter another service? Y/N:")
        if selection == 'Y' or selection == 'y':
            continue
        else:
            output.close()
            x = 1
            os.system("clear")
            menu()
#enables single entry for services by the user.
def createEntry():
    os.system("clear")
    Services = []
    Credentials = {}
    Service = raw_input('Please enter the service:'   )
    Services.append(raw_input('Please Enter your Username:' ))
    Services.append(raw_input('Please Enter your Password:' ))
    Credentials[Service] = Services
    output = open(".output.txt", "ab+")
    #saves user state of file containing login details for services.
    pickle.dump(Credentials, output)
    output.close()
    menuorquit()
#encrypts the contents of the file using AES encryption, detects filename and sets key based on user input.
def encrypt(key, filename):
    chunksize = 64*1024
    outputFile = "(encrypted)"+filename
    filesize = str(os.path.getsize(filename)).zfill(16)
    IV = ''
    for i in range(16):
        IV += chr(random.randint(0, 0xFF))
    encryptor = AES.new(key, AES.MODE_CBC, IV)
    with open(filename, 'rb') as infile:
        with open(outputFile, 'wb') as outfile:
            outfile.write(filesize)
            outfile.write(IV)
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += ' ' * (16 - (len(chunk) % 16))
                outfile.write(encryptor.encrypt(chunk))
                os.system('rm "' + filename + '"')
#decrypts the AES encrypted file when prompted.reads in the encrypted contents and decrypts it with the built in module.
def decrypt(key, filename):
    chunksize = 64*1024
    outputFile = filename[11:]
    with open(filename, 'rb') as infile:
        filesize = long(infile.read(16))
        IV = infile.read(16)
        decryptor = AES.new(key, AES.MODE_CBC, IV)
        with open(outputFile, 'wb') as outfile:
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                outfile.write(decryptor.decrypt(chunk))
            outfile.truncate(filesize)
#generates hash of password set for user  when prompted.
def getKey(password):
    hasher = SHA256.new(password)
    return hasher.digest()
#Allows user to enter service they wish to have displayed in the terminal.
def serviceDisplay():
    os.system("clear")
    service = raw_input("Please enter the service you wish to display.\nNOTE! this will display your username and password in plain text.\n")
    new_dict = pickleLoad()
    for key, value in new_dict.items():
        if key == service:
            print "Service: " + service + " Username: " + value[0] + " Password: " + value[1]
    menuorquit()
#allows user to delete service entry based on the key they pass in, if it exists it will delete. if not return to menu.
def serviceEdit():
    service = raw_input("Please enter the service you wish to delete.\n")
    new_dict = pickleLoad()
    for key, value in new_dict.items():
        if key == service:
            del new_dict[service]
            input_file = open(".output.txt", "wb")
            pickle.dump(new_dict, input_file)
            input_file.close()
            print "This has now been removed from the file!"
            menuorquit()
    else:
        if key != service:
            print "No service found, returning to the main menu!"
        menu()
#used by the single entry module in order to avoid writing over the contents of the file, acts as a merger.
def pickleLoad():
    input_file = open(".output.txt", "rb")
    new_dict = {}
    while True:
        try:
            pick = pickle.load(input_file)
        except EOFError:
            break
        else:
            new_dict.update(pick)
    input_file.close()
    return new_dict
#displays all contnets of pickled file and prints out to terminal.
def displayAll():
    new_dict = pickleLoad()
    for key, value in new_dict.items():
        print "Service: " + key + " Username: " + value[0] + " Password: " + value[1]
    menuorquit()
#option to go back to the main menu or quit, will initiate when certain actions have been performed.
def menuorquit():
    option = raw_input("Would you like to go back to the main menu or Quit the program? M/Q:")
    if option == 'M' or option == 'm':
        menu()
    elif option == 'Q' or option == 'q':
        exitProgram()
    else:
        print "Please enter M or Q only, not case sensetive."
        menuorquit()
#on exiting this is where the encryption will take palce, takes in the filename created when contents are written to a file, then encrypts.
def exitProgram():
    print "Please enter master password to encrypt/re-encrypt file!"
    password = getpass.getpass('Password:')
    if password == '':
        print 'No password entered! Please enter a valid password.'
        exitProgram()
    else:
        password_hash = hashlib.sha256(password).hexdigest()
        output = open('.hash.txt', 'wb')
        output.write(password_hash)
        output.close()
        encrypt(getKey(password), ".output.txt")
        sys.exit()

if __name__ == '__main__':
    main()
