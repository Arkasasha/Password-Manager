from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os
import argparse
import time
import bcrypt
import secrets
import string
import pyperclip

def encrypt_file(file_path, key_path):

    #Input Validation
    if not os.path.isfile(file_path):
        raise FileNotFoundError("File could not found: " + file_path)

    if os.path.dirname(key_path) and not os.path.exists(os.path.dirname(key_path)):
        raise FileNotFoundError("File could not found: " + key_path)
    
    # Read the key from file
    with open(key_path, 'rb') as f:
        key = f.read()

    # Encrypting the file
    cipher = AES.new(key, AES.MODE_EAX)
    with open(file_path, 'rb') as f:
        plaintext = f.read()
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    # Writes the encrypted file
    with open(file_path + ".aes", 'wb') as f:
        [f.write(x) for x in (cipher.nonce, tag, ciphertext)]

    # Deletes the original file
    try:
        os.remove(file_path)
    except:
        print("Original file could not deleted.")

def decrypt_file(file_path, key_path):

    #Input Validation
    if os.path.dirname(file_path) and not os.path.exists(os.path.dirname(file_path)):
        raise FileNotFoundError("File could not found: " + file_path)    

    if not os.path.isfile(key_path):
        raise FileNotFoundError("File could not found: " + key_path)    

    # Read the key from file
    with open(key_path, 'rb') as f:
        key = f.read()

    # Decrypt the file
    with open(file_path, 'rb') as f:
        nonce, tag, ciphertext = [f.read(x) for x in (16, 16, -1)]
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)

    # Write the decrypted file
    with open(file_path[:-4], 'wb') as f:
        f.write(plaintext)

def hash_password_bcrypt(password):
    # Generate a salt
    salt = bcrypt.gensalt()
    # Hash the password
    hashed = bcrypt.hashpw(password.encode(), salt)
    return hashed

def check_password_bcrypt(password, hashed):
    # Check the provided password against the hashed value
    return bcrypt.checkpw(password.encode(), hashed)

def save_new_password(file_path):
    os.system('cls')
    #Input Validation
    if os.path.dirname(file_path) and not os.path.exists(os.path.dirname(file_path)):
        raise FileNotFoundError("File could not found: " + file_path)
    
    #Gets new info
    login = input(f'Wite a login of the new password: ')
    password = input(f'Write the password: ')
    application = input(f'Write an application name/url: ')
    other_info = input(f'Any additional info: ')
    
    #Appends the file
    with open(file_path, 'a') as f:
        f.write(f'{login}\n')
        f.write(f'{password}\n')
        f.write(f'{application}\n')
        f.write(f'{other_info}\n')

def find_by_login(file_path):
    os.system('cls')
    #Input Validation
    if os.path.dirname(file_path) and not os.path.exists(os.path.dirname(file_path)):
        raise FileNotFoundError("File could not found: " + file_path)
    
    #Gets a login
    searchLogin = input('Enter serched login: ')
    
    #Seachs for a login
    line_number = -1
    found = 0
    with open(file_path, 'r') as f:
        for number, line in enumerate(f):
            if line_number == -1:
                if searchLogin in line:
                    line_number = number
            else:
                print(f'Your password: {line}')
                print(f'If you want to cpy the password to clipboard press (1), if not - enter')
                choice = input()
                
                if choice == '1':
                    pyperclip.copy(line)

                found = 1
                break
    if found == 0:
        print(f'Login {searchLogin} was not found.')
            
def update_by_login(file_path):
    os.system('cls')
    #Input Validation
    if os.path.dirname(file_path) and not os.path.exists(os.path.dirname(file_path)):
        raise FileNotFoundError("File could not found: " + file_path)
    
    #Gets a login
    searchLogin = input('Enter serched login: ')
    new_password = input('Enter new password: ')
    
    #Seachs for a login and write updated file
    line_number = -1
    found = 0
    with open('updated.txt', 'w') as new:
        with open(file_path, 'r') as f:
            for number, line in enumerate(f):
                if line_number == -1:
                    if searchLogin in line:
                        line_number = number
                    new.write(f'{line}')
                else:
                    new.write(f'{new_password}\n')
                    print(f'Password updated!')
                    found = 1
                    line_number = -1
    if found == 0:
        print(f'Login {searchLogin} was not found.')
    
    #Rewrites updated file into old one
    with open('updated.txt', 'r') as new:
        with open(file_path, 'w') as f:
            f.write(new.read())
            
    #Deletes updated file
    try:
        os.remove('updated.txt')

    except:
        print("Updated file could not deleted.")      

def delete_by_title(file_path):
    os.system('cls')
    #Input Validation
    if os.path.dirname(file_path) and not os.path.exists(os.path.dirname(file_path)):
        raise FileNotFoundError("File could not found: " + file_path)
    
    #Gets a login
    searchLogin = input('Enter serched login: ')
    
    login = ''
    password = ''
    application = ''
    other_info = ''
    
    #Seachs for a login and write updated file
    line_number = -1
    found = 0
    with open('updated.txt', 'w') as new:
        with open(file_path, 'r') as f:
            for number, line in enumerate(f):
                if line_number == -1:
                    if searchLogin in line:
                        line_number = number
                        login = line
                    else:
                        new.write(f'{line}')
                else:
                    if password != '':
                        if application != '':
                            other_info = line
                            
                            print(f'Do you really want to delete that data:')
                            print(f'Login: {login}', end = '')
                            print(f'Password: {password}', end = '')
                            print(f'Application/URL: {application}', end = '')
                            print(f'Addition info: {other_info}', end = '')
                            choice = input(f'Write "yes" if you want to continue: ')
                            
                            if choice != 'yes':
                                new.write(f'{login}{password}{application}{other_info}')
                                print(f'Data was not deleted.')
                            else:
                                print(f'Data was deleted.')
                            
                            line_number = -1
                            found = 1
                        else:
                            application = line
                    else:
                        password = line
    if found == 0:
        print(f'Login {searchLogin} was not found.')

    #Rewrites updated file into old one
    with open('updated.txt', 'r') as new:
        with open(file_path, 'w') as f:
            f.write(new.read())
            
    #Deletes updated file
    try:
        os.remove('updated.txt')

    except:
        print("Updated file could not deleted.") 

def menu(file_path):
    encr_file_path = file_path + '.aes'
    key_path = "key.txt"
    
    decrypt_file(encr_file_path, key_path)
    
    while True:
        os.system('cls')
        print(f'Choose the option (write only number):')
        print(f'(1) Add new password')
        print(f'(2) Find password')
        print(f'(3) Update password')
        print(f'(4) Delete password')
        print(f'(5) Close menu')
    
        option = input()

        if option == '1':
            save_new_password(file_path)
            continue
        if option == '2':
            find_by_login(file_path)
            continue
        if option == '3':
            update_by_login(file_path)
            continue
        if option == '4':
            delete_by_title(file_path)
            continue
        if option == '5':
            break
        print(f'No such option. Try again.')
        time.sleep(1)
        
    encrypt_file(file_path, key_path)
    
def generate_random_password(length=12, use_upper=True, use_digits=True, use_special=True):
    # Define the character sets to use in the password
    lower_case = string.ascii_lowercase
    upper_case = string.ascii_uppercase if use_upper else ''
    digits = string.digits if use_digits else ''
    special_chars = string.punctuation if use_special else ''

    # Combine all character sets
    all_chars = lower_case + upper_case + digits + special_chars

    if not all_chars:
        raise ValueError("No character sets selected for password generation.")

    # Generate the password using secrets.choice for cryptographic security
    password = ''.join(secrets.choice(all_chars) for _ in range(length))

    return password

def sign_in():
    username = ''
    password = ''
    os.system('cls')
    while True:
        username = input(f'Create your username: ')
        password = input(f'Create your password (write "rand" if you want to get a random password): ')
        
        if password == 'rand':
            length = int(input('Enter the lenth of the password: '))
            while True:
                gen_password = generate_random_password(length, use_upper=True, use_digits=True, use_special=True)
                print(f'Here is your password: {gen_password}')
                choice = input('If you like press (1), if not - (2)\n')
            
                if choice == '1':
                    password = gen_password
                    break
                if choice == '2':
                    continue
                if choice != '1' and choice != '2':
                    continue
        

    
        #Checks an existing user
        found = 0
        with open('user.txt', 'r') as f:
            for line in f:
                line = line.rstrip()
                if line == username:
                    found = 1
                    break
        if found == 0:
            break
        else:
            print('There is a user with such a nickname. Try something else.')
            print(f'If you want to try again press (1)')
            print(f'If you want to quit press (2)')
            choice = input()
            
            if choice == '1':
                continue
            if choice == '2':
                break
            if choice != '1' and choice != '2':
                print('There is no such option. Quiting logining.')
                break
    
    #Hashes a password     
    hashed_password = hash_password_bcrypt(password)
    user_path = 'users\\' + username + '.txt'
    user_password = 'users\\' + username + '_password.txt'

    #Appends user file
    with open('user.txt', 'a') as f:
        f.write(username)
        f.write('\n')
    
    #Seves password
    with open(user_password, 'wb') as f:
        f.write(hashed_password)
    
    #Creates user's file
    key_path = "key.txt"
    with open(user_path, 'w') as f:
        f.write('')
    encrypt_file(user_path, key_path)

    #Opens a menu
    print(f'Account created. Enjoy your service.')   
    menu(user_path)

def log_in():
    os.system('cls')
    user_path = ''
    while True:
        username = input(f'Write your username: ')
        password = input(f'Write your password: ')
        #Checks password
        allow = 0
        with open('user.txt', 'r') as f:
            for line_number, line in enumerate(f, 1):
                line = line.rstrip()
                if line == username:
                    user_password = 'users\\' + username + '_password.txt'
                    hashed_password = b''
                    with open(user_password, 'rb') as f:
                        hashed_password = f.read()
                    if check_password_bcrypt(password, hashed_password):
                        allow = 1
                        user_path = 'users\\' + username + '.txt'
        if allow == 1:
            print(f'You loged in succesfully!')
            menu(user_path)
            break
        else:
            print(f'Username or password is incorrect!')
            print(f'If you want to try again press (1)')
            print(f'If you want to quit press (2)')
            choice = input()
            
            if choice == '1':
                continue
            if choice == '2':
                break
            if choice != '1' and choice != '2':
                print('There is no such option. Quiting logining.')
                break

def start_menu():
    while True:
        os.system('cls')
        print('Choose an option (only number):')
        print('(1) Log in')
        print('(2) Register')
        print('(3) End program')
        choice = input()
    
        if choice == '1':
            log_in()
        if choice == '2':
            sign_in()
        if choice == '3':
            break
        if choice != '1' and choice != '2' and choice != '3':
            print('There is no such option. Try again.')
            time.sleep(3)
        
    

if __name__ == '__main__':
    if not os.path.exists('user.txt'):
        with open('user.txt', 'x') as f:
            f.write('')
    newpath = r'users'
    if not os.path.exists(newpath):
        os.makedirs(newpath)
    if not os.path.exists('key.txt'):
        key = input('Write 16 byts key for the AES algorithm:\n')
        while True:
            if len(key) != 16:
                print('Wrong lenth try again.')
                key = input()
                continue
            else:
                break
        with open('key.txt', 'w') as f:
            f.write(key)
    start_menu()
    
