from multiprocessing import Process, Queue

class PasswordCracker:
    def __init__(self, cpu_core, hash_compare_method):
        self.read_queue = Queue()
        self.write_queue = Queue()
        self.dictionary = []
        self.crack_target = []
        self.cpu_core = cpu_core
        self.hash_compare_method = hash_compare_method

    def load_dictionary(self, dictionary_file):
        with open(dictionary_file) as infile:
            dict = infile.readlines()
            self.dictionary = [line.strip('\n') for line in dict]

    def crack_password(self, user, hashed_password):
        print('[+] Cracking user %s.' % (user))
        reader = Process(target=self.dictionary_reader_worker)
        reader.start()
        crackers = [Process(target=self.crack_password_worker, args=(user, hashed_password, )) for x in range(self.cpu_core)]
        for cracker in crackers:
            cracker.start()
        reader.join()
        for cracker in crackers:
            cracker.join()
        self.write_queue.put(None)

    def crack_password_worker(self, user, hashed_password):
        while True:
            password = self.read_queue.get()
            if password is None:
                break
            if self.hash_compare_method(password, hashed_password):
                print('[+] User %s password found : %s' % (user, password))
                self.write_queue.put((user,password))
        self.read_queue.put(None)

    def dictionary_reader_worker(self):
        for password in self.dictionary:
            self.read_queue.put(password)
        self.read_queue.put(None)

    def create_result_file(self, result_filename = 'cracker_results.txt'):
        with open(result_filename, 'w') as outfile:
            count = 0
            while True:
                line = self.write_queue.get()
                if line is None:
                    break
                outfile.write('Username : %s == Password %s' % line + '\n')
                count += 1
            print('[+] Found %d password(s).' % (count))
