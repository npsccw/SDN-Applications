from gi.repository import Gtk, Gio, Gdk
from matplotlib.figure import Figure
from numpy import arange, pi, random, linspace
import matplotlib.cm as cm
from matplotlib.backends.backend_gtk3cairo import FigureCanvasGTK3Cairo as FigureCanvas


class SDNApp(Gtk.Window):
    def __init__(self):
        self.apps = {"analyzer": False, "topology": False, "fingerprint":False}
        Gtk.Window.__init__(self, title="NPS SDN Application")
        self.set_border_width(10)
        self.set_default_size(400, 200)

        hb = Gtk.HeaderBar()
        hb.set_show_close_button(True)
        hb.props.title = "Software-Defined Networking"
        self.back_button = Gtk.Button()
        self.back_button.add(Gtk.Arrow(Gtk.ArrowType.LEFT, Gtk.ShadowType.NONE))
        self.back_button.connect("clicked", self.switch_screens, "back")
        hb.pack_start(self.back_button)
        self.set_titlebar(hb)

        #The master container
        self.stack = Gtk.Stack()
        self.stack.set_transition_type(Gtk.StackTransitionType.SLIDE_LEFT_RIGHT)
        self.stack.set_transition_duration(100)
        self.stack.set_homogeneous(False)
        frame = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=5)
        frame.pack_start(self.stack, True, True, 0)

        #Splash screen
        vbox_splash = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=5)
        self.stack.add_named(vbox_splash, "splash")
        label = Gtk.Label("Select the passive applications you want to run")
        label.set_markup("Select the passive applications you want to run\n\
                    <small>Active applications will always run</small>")
        vbox_splash.pack_start(label, True, True, 0)
        

        hbox = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=5)
        vbox_splash.pack_start(hbox, True, True, 0)

        vbox_left = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=5)
        check = Gtk.CheckButton("Analyzer")
        check.connect("toggled", self.on_toggled, "analyzer")
        check.set_active(False)
        vbox_left.pack_start(check, True, True, 0)
        check = Gtk.CheckButton("Topology")
        check.connect("toggled", self.on_toggled, "topology")
        check.set_active(False)
        vbox_left.pack_start(check, True, True, 0)
        check = Gtk.CheckButton("Fingerprint")
        check.connect("toggled", self.on_toggled, "fingerprint")
        check.set_active(False)
        vbox_left.pack_start(check, True, True, 0)
        
        vbox_right = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=5)
        image = Gtk.Image()
        image.set_from_file("ccwlogo.gif")
        vbox_right.pack_start(image, True, True, 0)

        button = Gtk.Button("Run")
        button.connect("clicked", self.switch_screens, "forward")
        vbox_splash.pack_start(button, True, True, 0)

        hbox.pack_start(vbox_left, True, True, 0)
        hbox.pack_start(vbox_right, True, True, 0)

        #Squirtle Screen
        self.hbox_app = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=5)
        self.stack.add_named(self.hbox_app, "squirtle")
        
        #Flow Modifying Apps
        vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=5)
        self.hbox_app.pack_start(vbox, True, True, 0)
        label = Gtk.Label()
        label.set_markup("<big><b>Flow Manipulations</b></big>")

        vbox.pack_start(label, True, True, 0)

        stack = Gtk.Stack()
        # stack.set_transition_type(Gtk.StackTransitionType.SLIDE_LEFT_RIGHT)
        # stack.set_transition_duration(50)

        #Blacklist App
        stack_app = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        scrolledwindow = Gtk.ScrolledWindow()
        scrolledwindow.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scrolledwindow.set_min_content_height(200)
        stack_app.pack_start(scrolledwindow, True, True, 0)
        self.blacklist_text_buffer = Gtk.TextBuffer()
        self.blacklist_text_view = Gtk.TextView(buffer=self.blacklist_text_buffer)
        self.blacklist_text_view.set_editable(False)
        self.blacklist_text_view.set_cursor_visible(False)
        scrolledwindow.add(self.blacklist_text_view)
        self.blacklist_entry = Gtk.Entry()
        self.blacklist_entry.set_text("Enter an IP address")
        self.blacklist_entry.connect("event", self.clear_entry)
        stack_app.pack_start(self.blacklist_entry, True, True, 0)
        button_hbox = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=0)
        stack_app.pack_start(button_hbox, True, True, 0)
        button = Gtk.Button("Add")
        button.connect("clicked", self.modify_ip, ["blacklist", "add"])
        button_hbox.pack_start(button, True, True, 0)
        button = Gtk.Button("Remove")
        button.connect("clicked", self.modify_ip, ["blacklist", "remove"])
        button_hbox.pack_start(button, True, True, 0)
        stack.add_titled(stack_app, 'blacklist', 'Blacklist')

        #Sandbox App
        stack_app = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        scrolledwindow = Gtk.ScrolledWindow()
        scrolledwindow.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scrolledwindow.set_min_content_height(200)
        stack_app.pack_start(scrolledwindow, True, True, 0)
        self.sandbox_text_buffer = Gtk.TextBuffer()
        self.sandbox_text_view = Gtk.TextView(buffer=self.sandbox_text_buffer)
        self.sandbox_text_view.set_editable(False)
        self.sandbox_text_view.set_cursor_visible(False)
        scrolledwindow.add(self.sandbox_text_view)
        self.sandbox_entry = Gtk.Entry()
        self.sandbox_entry.set_text("Enter an IP address")
        self.sandbox_entry.connect("event", self.clear_entry)
        stack_app.pack_start(self.sandbox_entry, True, True, 0)
        button_hbox = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=0)
        stack_app.pack_start(button_hbox, True, True, 0)
        button = Gtk.Button("Add")
        button.connect("clicked", self.modify_ip, ["sandbox", "add"])
        button_hbox.pack_start(button, True, True, 0)
        button = Gtk.Button("Remove")
        button.connect("clicked", self.modify_ip, ["sandbox", "remove"])
        button_hbox.pack_start(button, True, True, 0)
        stack.add_titled(stack_app, 'sandbox', 'Sandbox')

        #Packet Corrutpt App
        stack_app = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        scrolledwindow = Gtk.ScrolledWindow()
        scrolledwindow.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scrolledwindow.set_min_content_height(200)
        stack_app.pack_start(scrolledwindow, True, True, 0)
        self.corrupt_text_buffer = Gtk.TextBuffer()
        self.corrupt_text_view = Gtk.TextView(buffer=self.corrupt_text_buffer)
        self.corrupt_text_view.set_editable(False)
        self.corrupt_text_view.set_cursor_visible(False)
        scrolledwindow.add(self.corrupt_text_view)
        self.corrupt_entry = Gtk.Entry()
        self.corrupt_entry.set_text("Enter an IP address")
        self.corrupt_entry.connect("event", self.clear_entry)
        stack_app.pack_start(self.corrupt_entry, True, True, 0)
        button_hbox = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=0)
        stack_app.pack_start(button_hbox, True, True, 0)
        button = Gtk.Button("Add")
        button.connect("clicked", self.modify_ip, ["corrupt", "add" ])
        button_hbox.pack_start(button, True, True, 0)
        button = Gtk.Button("Remove")
        button.connect("clicked", self.modify_ip, ["corrupt", "remove"])
        button_hbox.pack_start(button, True, True, 0)
        stack.add_titled(stack_app, 'corrupt', 'Corrupt')

        stack_switcher = Gtk.StackSwitcher()
        stack_switcher.set_stack(stack)

        vbox.pack_start(stack_switcher, True, True, 0)
        vbox.pack_start(stack, True, True, 0)

        #Packet Manipulations
        label = Gtk.Label()
        label.set_markup("<big><b>Packet Manipulations</b></big>")
        vbox.pack_start(label, True, True, 0)
        stack = Gtk.Stack()
        # stack.set_transition_type(Gtk.StackTransitionType.SLIDE_LEFT_RIGHT)
        # stack.set_transition_duration(500)
        
        #Ping app
        stack_app = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        scrolledwindow = Gtk.ScrolledWindow()
        scrolledwindow.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scrolledwindow.set_min_content_height(200)
        stack_app.pack_start(scrolledwindow, True, True, 0)
        self.ping_text_buffer = Gtk.TextBuffer()
        self.ping_text_view = Gtk.TextView(buffer=self.ping_text_buffer)
        self.ping_text_view.set_editable(False)
        self.ping_text_view.set_cursor_visible(False)
        scrolledwindow.add(self.ping_text_view)
        self.ping_entry = Gtk.Entry()
        self.ping_entry.set_text("Enter an IP address")
        self.ping_entry.connect("event", self.clear_entry)
        stack_app.pack_start(self.ping_entry, True, True, 0)
        button = Gtk.Button("Ping")
        button.connect("clicked", self.packet_send, "ping")
        stack_app.pack_start(button, True, True, 0)
        button = Gtk.Button("Clear History")
        button.connect("clicked", self.clear_history)
        stack_app.pack_start(button, True, True, 0)
        stack.add_titled(stack_app, "ping", "Ping")

        #TCP Rst
        stack_app = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        scrolledwindow = Gtk.ScrolledWindow()
        scrolledwindow.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scrolledwindow.set_min_content_height(200)
        stack_app.pack_start(scrolledwindow, True, True, 0)
        self.tcp_text_buffer = Gtk.TextBuffer()
        self.tcp_text_view = Gtk.TextView(buffer=self.tcp_text_buffer)
        self.tcp_text_view.set_editable(False)
        self.tcp_text_view.set_cursor_visible(False)
        scrolledwindow.add(self.tcp_text_view)
        self.tcp_entry = Gtk.Entry()
        self.tcp_entry.set_text("Enter an IP address")
        self.tcp_entry.connect("event", self.clear_entry)
        stack_app.pack_start(self.tcp_entry, True, True, 0)
        button = Gtk.Button("Ping")
        button.connect("clicked", self.packet_send, "tcp")
        stack_app.pack_start(button, True, True, 0)
        button = Gtk.Button("Clear History")
        button.connect("clicked", self.clear_history)
        stack_app.pack_start(button, True, True, 0)
        stack.add_titled(stack_app, "tcp", "TCP RST")


        stack_switcher = Gtk.StackSwitcher()
        stack_switcher.set_stack(stack)
        vbox.pack_start(stack_switcher, True, True, 0)
        vbox.pack_start(stack, True, True, 0)

        graph_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self.hbox_app.pack_start(graph_box, True, True, 0)

        self.analyzer_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        fig = Figure(figsize=(5,5), dpi=100)
        ax = fig.add_subplot(111, projection='polar')

        N=20
        theta = linspace(0.0, 2*pi, N, endpoint=False)
        radii = 10 * random.rand(N)
        width = pi / 4 * random.rand(N)


        bars = ax.bar(theta, radii, width=width, bottom=0.0)

        for r, bar in zip(radii, bars):
            bar.set_facecolor(cm.jet(r / 10.))
            bar.set_alpha(0.5)

        ax.plot()
        graph_box.pack_start(self.analyzer_box, True, True, 0)

        canvas = FigureCanvas(fig)
        canvas.set_size_request(400,200)
        self.analyzer_box.pack_start(canvas, True, True, 0)

        self.topology_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        fig = Figure(figsize=(5,5), dpi=100)
        ax = fig.add_subplot(111, projection='polar')

        N=20
        theta = linspace(0.0, 2*pi, N, endpoint=False)
        radii = 10 * random.rand(N)
        width = pi / 4 * random.rand(N)


        bars = ax.bar(theta, radii, width=width, bottom=0.0)

        for r, bar in zip(radii, bars):
            bar.set_facecolor(cm.jet(r / 10.))
            bar.set_alpha(0.5)

        ax.plot()

        
        graph_box.pack_start(self.topology_box, True, True, 0)

        canvas = FigureCanvas(fig)
        canvas.set_size_request(400,200)
        self.topology_box.pack_start(canvas, True, True, 0)











        self.add(frame)

    def initial_show(self):
        self.show_all()
        self.back_button.hide()
        self.analyzer_box.hide()
        self.topology_box.hide()
        self.set_resizable(False)

    def on_toggled(self, button, data):
        self.apps[data] = button.get_active()
        print(data + " pressed: " + `self.apps[data]`)

    def switch_screens(self, button, data):
        if data == "back":
            self.back_button.hide()
            self.stack.set_visible_child_name("splash")
            self.analyzer_box.hide()
            self.topology_box.hide()
            self.set_size_request(400, 350)
            
        elif data == "forward":
            self.back_button.show()
            self.stack.set_visible_child_name("squirtle")
            if self.apps["analyzer"]:  
                self.analyzer_box.show()

            if self.apps["topology"]:
                self.topology_box.show()


    def modify_ip(self, button, data):
        data = data[:2]
        if data[0] == "blacklist":
            self._mod_helper(self.blacklist_entry.get_text(), self.blacklist_text_buffer,\
                            data[1])
            self.clear_entry(self.blacklist_entry, None, user_call=True)
        elif data[0] == "sandbox":
            self._mod_helper(self.sandbox_entry.get_text(), self.sandbox_text_buffer,\
                            data[1])
            self.clear_entry(self.sandbox_entry, None, user_call=True)
        elif data[0] == "corrupt":
            self._mod_helper(self.corrupt_entry.get_text(), self.corrupt_text_buffer,\
                            data[1])
            self.clear_entry(self.corrupt_entry, None, user_call=True)

    def _mod_helper(self, ip, buff, mode):
        if mode == "add":
            start, end = buff.get_bounds()
            current_view = buff.get_text(start, end, False)
            current_list = current_view.split("\n")
            if ip in current_list: return
            current_view += "\n" + ip
            buff.set_text(current_view)


    def clear_entry(self, entry, event, user_call=False):
        if user_call or event.type == Gdk.EventType.BUTTON_RELEASE:
            entry.set_text("")

    def packet_send(self, button, data):
        if data == "ping":
            self.add_history(self.ping_text_buffer)
        elif data == "tcp":
            self.add_history(self.tcp_text_buffer)

    def add_history(self, buff):
        print("I'm too sleepy")

    def clear_history(self, button, data=None):
        print("clearing data")

if __name__ == "__main__":
    win = SDNApp()
    win.connect("delete-event", Gtk.main_quit)
    win.initial_show()
    Gtk.main()