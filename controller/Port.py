import time

class Port(object):
    # This is data class passed by EventPortXXX
    def __init__(self, dpid, ofproto, ofpport):
        super(Port, self).__init__()

        self.dpid = dpid
        self._ofproto = ofproto
        self._config = ofpport.config
        self._state = ofpport.state

        self.port_no = ofpport.port_no
        self.hw_addr = ofpport.hw_addr
        self.name = ofpport.name

    def is_reserved(self):
        return self.port_no > self._ofproto.OFPP_MAX

    def is_down(self):
        return (self._state & self._ofproto.OFPPS_LINK_DOWN) > 0 \
            or (self._config & self._ofproto.OFPPC_PORT_DOWN) > 0

    def is_live(self):
        # NOTE: OF1.2 has OFPPS_LIVE state
        #       return (self._state & self._ofproto.OFPPS_LIVE) > 0
        return not self.is_down()

    def to_dict(self):
        return {'dpid': dpid_to_str(self.dpid),
                'port_no': port_no_to_str(self.port_no),
                'hw_addr': self.hw_addr,
                'name': self.name.rstrip('\0')}
                
    # for Switch.del_port()
    def __eq__(self, other):
        return self.dpid == other.dpid and self.port_no == other.port_no

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash((self.dpid, self.port_no))

    def __str__(self):
        LIVE_MSG = {False: 'DOWN', True: 'LIVE'}
        return 'Port<dpid=%s, port_no=%s, %s>' % \
            (self.dpid, self.port_no, LIVE_MSG[self.is_live()])

class PortState(dict):
    # dict: int port_no -> OFPPort port
    # OFPPort is defined in ryu.ofproto.ofproto_v1_X_parser
    def __init__(self):
        super(PortState, self).__init__()

    def add(self, port_no, port):
        self[port_no] = port

    def remove(self, port_no):
        del self[port_no]

    def modify(self, port_no, port):
        self[port_no] = port


class PortData(object):
    def __init__(self, is_down, lldp_data):
        super(PortData, self).__init__()
        self.is_down = is_down
        self.lldp_data = lldp_data
        self.timestamp = None
        self.sent = 0

    def lldp_sent(self):
        self.timestamp = time.time()
        self.sent += 1

    def lldp_received(self):
        self.sent = 0

    def lldp_dropped(self):
        return self.sent

    def clear_timestamp(self):
        self.timestamp = None

    def set_down(self, is_down):
        self.is_down = is_down

    def __str__(self):
        return 'PortData<live=%s, timestamp=%s, sent=%d>' \
            % (not self.is_down, self.timestamp, self.sent)


class PortDataState(dict):
    # dict: Port class -> PortData class
    # slimed down version of OrderedDict as python 2.6 doesn't support it.
    _PREV = 0
    _NEXT = 1
    _KEY = 2

    def __init__(self):
        super(PortDataState, self).__init__()
        self._root = root = []          # sentinel node
        root[:] = [root, root, None]    # [_PREV, _NEXT, _KEY]
                                        # doubly linked list
        self._map = {}

    def _remove_key(self, key):
        link_prev, link_next, key = self._map.pop(key)
        link_prev[self._NEXT] = link_next
        link_next[self._PREV] = link_prev

    def _append_key(self, key):
        root = self._root
        last = root[self._PREV]
        last[self._NEXT] = root[self._PREV] = self._map[key] = [last, root,
                                                                key]

    def _prepend_key(self, key):
        root = self._root
        first = root[self._NEXT]
        first[self._PREV] = root[self._NEXT] = self._map[key] = [root, first,
                                                                 key]

    def _move_last_key(self, key):
        self._remove_key(key)
        self._append_key(key)

    def _move_front_key(self, key):
        self._remove_key(key)
        self._prepend_key(key)

    def add_port(self, port, lldp_data):
        if port not in self:
            self._prepend_key(port)
            self[port] = PortData(port.is_down(), lldp_data)
        else:
            self[port].is_down = port.is_down()

    def lldp_sent(self, port):
        port_data = self[port]
        port_data.lldp_sent()
        self._move_last_key(port)
        return port_data

    def lldp_received(self, port):
        self[port].lldp_received()

    def move_front(self, port):
        port_data = self.get(port, None)
        if port_data is not None:
            port_data.clear_timestamp()
            self._move_front_key(port)

    def set_down(self, port):
        is_down = port.is_down()
        port_data = self[port]
        port_data.set_down(is_down)
        port_data.clear_timestamp()
        if not is_down:
            self._move_front_key(port)
        return is_down

    def get_port(self, port):
        return self[port]

    def del_port(self, port):
        del self[port]
        self._remove_key(port)

    def __iter__(self):
        root = self._root
        curr = root[self._NEXT]
        while curr is not root:
            yield curr[self._KEY]
            curr = curr[self._NEXT]

    def clear(self):
        for node in self._map.values():
            del node[:]
        root = self._root
        root[:] = [root, root, None]
        self._map.clear()
        dict.clear(self)

    def items(self):
        'od.items() -> list of (key, value) pairs in od'
        return [(key, self[key]) for key in self]

    def iteritems(self):
        'od.iteritems -> an iterator over the (key, value) pairs in od'
        for k in self:
            yield (k, self[k])

