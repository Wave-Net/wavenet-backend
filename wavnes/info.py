import time
import threading


class PacketTimeInfo:
    def __init__(self):
        self.lock = threading.Lock()
        self.reset()

    def reset(self):
        with self.lock:
            self.index = 0
            self.start_time = time.time()
            self.prev_time = 0.0
            self.curr_time = 0.0

    def update(self, packet):
        with self.lock:
            self.index += 1
            self.prev_time = self.curr_time
            self.curr_time = packet.time

    def get_time_info(self):
        with self.lock:
            return {
                'index': self.index,
                'timestamp': '{:.6f}'.format(self.curr_time),
                'time_of_day': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.curr_time)),
                'seconds_since_beginning': '{:.6f}'.format(float(self.curr_time - self.start_time)),
                'seconds_since_previous': '{:.6f}'.format(float(self.curr_time - self.prev_time)),
            }


class PacketStatInfo:
    def __init__(self, target_ip):
        self.target_ip = target_ip
        self.lock = threading.Lock()
        self.reset()

    def reset(self):
        with self.lock:
            self.cur_stat = {'send_pkt': 0, 'recv_pkt': 0,
                             'send_data': 0, 'recv_data': 0}

    def update(self, src, dst, data):
        with self.lock:
            if src == self.target_ip:
                self.cur_stat['send_pkt'] += 1
                self.cur_stat['send_data'] += data
                return
            if dst == self.target_ip:
                self.cur_stat['recv_pkt'] += 1
                self.cur_stat['recv_data'] += data

    @staticmethod
    def get_delta(cur_stat, prev_stat):
        return {key: cur_stat[key] - prev_stat[key]
                for key in cur_stat}

    def get_total(self):
        with self.lock:
            return self.cur_stat.copy()
