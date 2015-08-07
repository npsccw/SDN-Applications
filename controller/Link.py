"""
Helper class for ControlNode for 
topology detection.  This data
structure is how ControlNode represents
switch links.
"""
import time

class Link:

    def __init__(self, src, dst):
        self.src = src
        self.dst = dst
        self.weight = 1
        self.t1 = 0
        self.t2 = 0 
        self.prev = [0,0] #[Rx,Tx]
        self.cur = [0,0]  #[Rx,Tx]
        self.max_R = 1e8 / 8.0
        self.updated = False

    def __repr__(self):
        return "(" + `self.src` + "," + `self.dst` + ") - " + `self.weight`

    def __eq__(self, link):
        return self.src == link.src and self.dst == link.dst
	
    def to_dict(self):
        d = {'src': self.src.to_dict(),
             'dst': self.dst.to_dict()}
        return d

    # this type is used for key value of LinkState
    def __eq__(self, other):
        return self.src == other.src and self.dst == other.dst

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash((self.src, self.dst))

    def __str__(self):
        return 'Link: %s to %s' % (self.src, self.dst)

    def elapse_time(self, cur, t):
	    self.prev = self.cur
	    self.cur = cur
	    self.t1 = self.t2
	    self.t2 = t
	    self._update_link_weight()
	
    def _update_link_weight(self):
	    dt = self.t2 - self.t1
	    if dt < 0:  
	        dt += 60
	    #overflow
	    if self.prev[0] > self.cur[0]:
	        self.cur[0] += pow(2,32)
	    if self.prev[1] > self.cur[1]:
	        self.cur[1] += pow(2,32)
            
	    Rx = float((self.cur[0] - self.prev[0])) / dt
	    Tx = float((self.cur[1] - self.prev[1])) / dt
	
	    self.weight = (1.0 - Rx/self.max_R) * (1.0 - Tx/self.max_R)
	    
class LinkState(dict):
    # dict: Link class -> timestamp
    def __init__(self):
        super(LinkState, self).__init__()
        self._map = {}

    def get_peer(self, src):
        return self._map.get(src, None)

    def update_link(self, src, dst):
        link = Link(src, dst)

        self[link] = time.time()
        self._map[src] = dst

        # return if the reverse link is also up or not
        rev_link = Link(dst, src)
        return rev_link in self

    def link_down(self, link):
        del self[link]
        del self._map[link.src]

    def rev_link_set_timestamp(self, rev_link, timestamp):
        # rev_link may or may not in LinkSet
        if rev_link in self:
            self[rev_link] = timestamp

    def port_deleted(self, src):
        dst = self.get_peer(src)
        if dst is None:
            raise KeyError()

        link = Link(src, dst)
        rev_link = Link(dst, src)
        del self[link]
        del self._map[src]
        # reverse link might not exist
        self.pop(rev_link, None)
        rev_link_dst = self._map.pop(dst, None)

        return dst, rev_link_dst
	
