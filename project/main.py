import time
import threading
from queue import Queue
import socket
import optparse
from services import services
from packet import syn_scann,ack_scann,fin_scann,window_scann

parser = optparse.OptionParser("-t <Host> -p <Port Start>-<Port Stop> -s <TypeScan> -d <Timeout>")
parser.add_option('-t', dest='host', type='string', help='Specify Host IP Address')
parser.add_option('-p', dest='port', type='string', help='Specify domein Port ', default='0-65535')
parser.add_option('-s', dest='type_scan', type='string', help='Specify Type of Scan: sC:Connect Scan ,sA:Ack Scan \t,sS:Syn Scan ,sF:Fin Scan ,sW:Windows Scan', default='sC')
parser.add_option('-d', dest='Delay', type='int', help='Specify Delay Time', default=0.1)
(options, args) = parser.parse_args()
port = str(options.port)
port_start, port_stop = port.split('-')
port_start = int(port_start)
port_stop =int(port_stop)
timeout = options.Delay
type_scan = options.type_scan
target = options.host


socket.setdefaulttimeout(0.53)

try:
    t_IP = socket.gethostbyname(target)
except:
    print('Cannot resolve %s: Unknown host' % target)
    exit()

if port_start > port_stop:
    print('can not scan this ports')
    exit()

ports = port_stop - port_start
print('Interesting {} ports on {}'.format(ports,t_IP))
print('PORT \t STATE \t\t SERVICE')


def connect_scan(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        conn = s.connect((t_IP, port))
        try:
              print('{}/tcp \t open \t\t {}'.format(port, services[str(port)]))
        except:
                print('{}/tcp \t open \t '.format(port))
        conn.close()
    except:
        pass

    time.sleep(timeout)
def threader():
    while True:
        worker = q.get()
        if type_scan=='sC':
         connect_scan(worker)
        elif type_scan=='sS':
          syn_scann(worker,t_IP,timeout)

        elif type_scan=='sA':
            ack_scann(worker,t_IP,timeout)

        elif type_scan=='sF':
            fin_scann(worker,t_IP,timeout)

        elif type_scan=='sW':
            window_scann(worker,t_IP,timeout)


        q.task_done()



q = Queue()

startTime = time.time()

for x in range(15):

    t = threading.Thread(target=threader)
    t.daemon = True
    t.start()

for worker in range(port_start,port_stop+1):
    q.put(worker)

q.join()


runtime = float("%0.2f" % (time.time() - startTime))
print("Run Time: ", runtime, "seconds")