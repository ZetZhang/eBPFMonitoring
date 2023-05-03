import threading
import time

class TestThread(threading.Thread):
    def run(self):
        time.sleep(2)

if __name__ == '__main__':
    counter = 0
    for i in range(100000):
        counter += 1
        t = TestThread()
        t.start()
        if i % 10 == 0:
            print("Current number of threads: ", counter)
    time.sleep(10)
    print("All threads finished.")
