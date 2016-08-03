import crypt
import argparse
import time
from password_cracker_core.password_cracker import PasswordCracker



class ShadowPasswordCracker(PasswordCracker):
    def __init__(self, cpu_core):
        PasswordCracker.__init__(self, cpu_core, self.unix_shadow_compare)
        self.shadow = []
        self.shadow_special_characters = ('!', '*', '')

    def unix_shadow_compare(self, passwd, hashed_passwd):
        split_hashed = hashed_passwd.split('$')
        salt = '$%s$%s' % (split_hashed[1], split_hashed[2])
        return crypt.crypt(passwd, salt) == hashed_passwd

    def load_shadow(self, shadow_file):
        with open(shadow_file) as infile:
            shad = infile.readlines()
            self.shadow = [line.strip('\n') for line in shad]

    def crack_shadow(self):
        for row in self.shadow:
            row = row.split(':')
            if row[1] not in self.shadow_special_characters:
                self.crack_password(row[0], row[1])



if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("dictionary_file", help="Specify the dictionary file location.")
    parser.add_argument("shadow_file", help="Specify the shadow file location.")
    parser.add_argument("-r","--result", help="Create a result file for successful cracked password with filename specified.")
    args = parser.parse_args()
    start_time = time.time()
    pwd_cracker = ShadowPasswordCracker(4)
    pwd_cracker.load_dictionary(args.dictionary_file)
    pwd_cracker.load_shadow(args.shadow_file)
    pwd_cracker.crack_shadow()
    if args.result:
        pwd_cracker.create_result_file(args.result)
    duration = time.time() - start_time
    minutes, seconds = divmod(duration, 60)
    hours, minutes = divmod(minutes, 60)
    print('[+] Finish in %d hours %d minutes %d seconds' % (hours, minutes, seconds))

