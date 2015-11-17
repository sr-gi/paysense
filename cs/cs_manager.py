import threading
from cs import CS
from urllib2 import URLError

__author__ = 'sdelgado'

ROOT_DIRECTORY = 'CSs/CS'
CS_COUNT = 10
INTERVAL = 3600


def get_data_directory(index):
    return ROOT_DIRECTORY + str(index) + '/'


def report_data(cs, data, index):
    # Report data
    response = cs.report_data(data)
    print "CS" + str(index) + ": " + str(response)

    # Set timer. Waiting time from 1 hour (index = 0) to 10 hours (index = 9)
    time = (index + 1) * INTERVAL

    # Set the thread timer
    t = threading.Timer(time, report_data, args=(cs, data, index))
    t.start()


def cs_control():
    for i in range(CS_COUNT):
        cs = CS(get_data_directory(i))

        # Test data
        data = '34512343291048'

        # Launch the first thread without waiting (the first time)
        if i is 0:
            report_data(cs, data, i)
        else:
            # Set timer. Waiting time from 2 hour (index = 1) to 10 hours (index = 9)
            time = (i + 1) * INTERVAL
            # Set the thread timer
            t = threading.Timer(time, report_data, args=(cs, data, i))
            t.start()


def certification_test(count=1000):
    for i in range(count):
        cs = CS(get_data_directory(i))
        r = cs.registration()
        assert type(r) is not URLError and r.status_code is 200
    return r.reason


def main():
    #pass
    # cs = CS("CSs/CS_0/")
    # from M2Crypto import EVP
    # pk = EVP.load_key("CSs/CS_0/private/paysense.key")
    # cs.generate_new_identity("mpzg9PJ1jNh5NfAU49gcB6zUKJBuMPwEqi", "mjtqnrY4MC2BGdeas9nN3JyqcvM9weFLB3", pk)
    # for i in range(4):
    #     cs = CS("_test/"+str(i)+"/")
    #     t = threading.Thread(target=cs.coinjoin_reputation_exchange, args=(10000,))
    #     t.start()

    btc_adddrs = ["", "", "", ""]

    for i in range(4):
        cs = CS("CSs/REP_EX_"+str(i)+"/")
        #cs.self_reputation_exchange("mjZJ8ovUXKv6D4GPM91Vq5sGW9AnhSo4dL", btc_adddrs[i])
        cs.registration()

if __name__ == '__main__':
    main()
