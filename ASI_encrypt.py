import os
import random

class Crypto():

    def __init__ (self):
        self.key = 'MASTER_KEY'
        self.MASTER_KEY = os.getenv(self.key) 
        if not isinstance(self.MASTER_KEY, str):
            print("Generating New Key!")
            self.MASTER_KEY = self.GenerateEncryptionKey()
            os.environ[self.key] = self.MASTER_KEY
        else:
            print("Key Found!")

    def GenerateEncryptionKey(self):
        """
        Generate encryption key

        Return: string -- key for encryption algorithm
        
        Keyword arguments: None
        """
        key_bits = 128 # Encryption key size

        def get_sum(hex_value):
            hex_sum = 0
            hex_sum += ord(hex_value[0])
            hex_sum -= ord(hex_value[1])

            return hex_sum

        key = ""
        random_nums = []
        hexa_values = []
        sorted_hexa = []
        for i in range(0,256):
            hexa_values.append(str(hex(i+256)).lstrip("0x").rstrip("L")[1:])

        while len(hexa_values) > 0:
            value = hexa_values.pop(0)
            new_hexa_sum = get_sum(value)
            if new_hexa_sum == 0 or new_hexa_sum <= -40 or new_hexa_sum >= 45:
                continue
            else:
                sorted_hexa.append(value)

        start = 0
        end = len(sorted_hexa) - 1

        for i in range(key_bits):
            rand = random.randint(start, end)
            random_nums.append(rand)

        for i in range(key_bits):
            key += sorted_hexa[random_nums[i]]
            if (i > 0 and i % 4 == 0 and i < key_bits - 1):
                key += "-"

        return key

    def get_encryption_key(self):
        """
        Modifies the encryption key during encryption and decryption.

        Return: string -- modified encryption/decryption key
        
        Keyword arguments: None
        """
        encryption_key = self.MASTER_KEY.split('-')
        if len(encryption_key) > 10:
            key = encryption_key.pop(0)
        else:
            key = encryption_key.pop(0)
            encryption_key.append(key)
        self.MASTER_KEY = "-".join(encryption_key)
        
        return "".join(encryption_key)

    def encode(self, value):
        """
        Encrypts any value provided.

        Return: string -- encrypted unicode characters
        
        Keyword arguments: value -- data to encrypt.
        """
        self.MASTER_KEY = os.getenv(self.key)
        encoded_str = list()
        value = str(value)
        add = True
        for char in value:
            encoded_bytes = None
            encryption_key = self.get_encryption_key()
            for key in encryption_key:
                key_bytes = ord(key)
                if encoded_bytes == None:
                    encoded_bytes = ord(char)
                if add:
                    encoded_bytes += key_bytes
                    add = False
                else:
                    encoded_bytes -= key_bytes
                    add = True
            try:
                encoded_char = chr(encoded_bytes)
                if encoded_char.isdigit():
                    encoded_str.append(str(encoded_bytes) + '+')
                else:
                    encoded_str.append(encoded_char)
            except ValueError:
                encoded_char = abs(encoded_bytes)
                encoded_str.append(str(encoded_char) + '-')

        return ''.join(encoded_str)

    def decode(self, value):
        """
        Decrypts any value provided using the class master key.

        Return: string -- decoded unicode characters
        
        Keyword arguments: value -- data to decrypt.
        """
        self.MASTER_KEY = os.getenv(self.key)
        decoded_str = list()
        value = str(value)
        next_char = True
        add = False
        index = 0
        def get_next_value(idx, values):
            char_str = list()
            max_idx = len(values) -1
            size = len(values)
            multi_values = False
            next_value = False

            while True:
                if idx <= max_idx:
                    next_value = values[idx]
                else:
                    next_value = False

                if isinstance(next_value, bool):
                    if len(char_str) > 1:
                        idx = len(values)
                        next_value = int("".join(char_str))
                        break
                    else:
                        idx = len(values)
                        break
                else:     
                    if not next_value.isdigit() and not multi_values:
                        idx += 1
                        break
                    if next_value.isdigit():
                        multi_values = True
                        char_str.append(next_value)
                        idx += 1
                    else:
                        if next_value == '-': 
                            next_value = -int("".join(char_str))
                            idx += 1
                        elif next_value == '+': 
                            next_value = int("".join(char_str))
                            idx += 1
                        else:
                            next_value = int("".join(char_str))
                        break

            return (idx, next_value)

        while True:
            index, next_char = get_next_value(index, value)
            encoded_bytes = None
            if next_char == False:
                break
            
            decryption_key = self.get_encryption_key()
            for key in decryption_key:
                key_bytes = ord(key)
                if encoded_bytes == None:
                    if not isinstance(next_char, int):
                        encoded_bytes = ord(next_char)
                    else:
                        encoded_bytes = next_char
                if add:
                    encoded_bytes += key_bytes
                    add = False
                else:
                    encoded_bytes -= key_bytes
                    add = True
                    
            decoded_char = chr(encoded_bytes)
            decoded_str.append(decoded_char)

        return "".join(decoded_str)

if __name__ == '__main__':
    encrypt = Crypto()
    encrypt.get_encryption_key()
    value = input("What would you like to encrypt?")
    #value = 'Password2000'
    encoded_value = encrypt.encode(value)
    print(f"Encrypted Value = {encoded_value}")
    print(f"Decrypted Value = {encrypt.decode(encoded_value)}")