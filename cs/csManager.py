import threading
from cs import CS

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


def certification_test():
    for i in range(1000):
        cs = CS(get_data_directory(i))
        r = cs.registration()
        assert r == "OK"
    print "END"


def main():
    for i in range(CS_COUNT):
        cs = CS(get_data_directory(i))
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

if __name__ == '__main__':
    main()
