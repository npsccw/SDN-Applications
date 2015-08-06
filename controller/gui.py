from gi.repository import Gtk, Gio, Gdk
from matplotlib.figure import Figure
from numpy import arange, pi, random, linspace
import matplotlib.cm as cm
from matplotlib.backends.backend_gtk3cairo import FigureCanvasGTK3Cairo as FigureCanvas
from subprocess import Popen, PIPE
import signal

class SDNApp(Gtk.Window):
    def __init__(self, connection=None):
        self.controller = None
	self.apps = {"analyze": False, "topology": False, "fingerprint":False}
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
        check.connect("toggled", self.on_toggled, "analyze")
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
        button.connect("clicked", self.run)
        vbox_splash.pack_start(button, True, True, 0)

        button = Gtk.Button("Restart Controller")
        button.connect("clicked", self.restart_controller)
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
        self.tcp_entry.set_text("NOT WORKING DO NOT TRY")
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

        def tool(button):
            print("I'm a new button!")

        #Network Toolbox
        vgrid = Gtk.Grid()
        label = Gtk.Label()
        label.set_markup("<big><b>Network Toolbox</b></big>")
        vgrid.attach(label, 0,0,1,1)
        vgrid.set_row_spacing(10)
        button = Gtk.Button("Clear All Flows")
        button.connect("clicked", self.send_command, "self.clear_all_flows()")
        vgrid.attach(button, 0,1,1,2)
        button = Gtk.Button("Turn On All Ports")
        button.connect("clicked", self.send_command, "self.switch_on_all_ports()")
        vgrid.attach(button, 0,3,1,2)
        button = Gtk.Button("Generate Spanning Tree")
        button.connect("clicked", self.send_command, "self.create_spanning_tree()")
        vgrid.attach(button, 0,5,1,2)
        button = Gtk.Button("Map Hosts")
        button.connect("clicked", self.send_command, "self.map_hosts(0)")
        vgrid.attach(button, 0,7,1,2)
        button = Gtk.Button("New Button")
        button.connect("clicked", tool)
        vgrid.attach(button, 0,9,1,2)
        button = Gtk.Button("New Button")
        button.connect("clicked", tool)
        vgrid.attach(button, 0,11,1,2)
        self.hbox_app.pack_start(vgrid, True, True, 0)



        self.add(frame)

    def restart_controller(self, button, data=None):
    	if self.controller:
    	    self.controller.terminate()
    	self.controller = Popen(["sudo", "ryu-manager", "ControlNode.py"])

    def run(self, button, data=None):
        with open("control_node_settings", "w") as f:
            for app in self.apps:
                f.write("self." + app + " = " + `self.apps[app]` + "\n")
        if self.controller:
	    print(self.controller)
            self.controller.send_signal(signal.SIGUSR1)
            print("Controller exists")
        else:
            self.controller = Popen(["sudo", "ryu-manager", "ControlNode.py"])
        self.switch_screens(None, "forward")

    def send_command(self, button, data):
        with open("commands", "a") as f:
            f.write(data + "\n")
            f.flush()

    def initial_show(self):
        self.show_all()
        self.back_button.hide()
        self.set_resizable(False)

    def on_toggled(self, button, data):
        self.apps[data] = button.get_active()
        print(data + " pressed: " + `self.apps[data]`)

    def switch_screens(self, button, data):
        if data == "back":
            self.back_button.hide()
            self.stack.set_visible_child_name("splash")
            self.set_size_request(400, 350)
            
        elif data == "forward":
            self.back_button.show()
            self.stack.set_visible_child_name("squirtle")

    def modify_ip(self, button, data):
        data = data[:2]
        if data[0] == "blacklist":
            self._mod_helper(self.blacklist_entry.get_text(), self.blacklist_text_buffer,\
                            data[1], "blacklist")
            self.clear_entry(self.blacklist_entry, None, user_call=True)
        elif data[0] == "sandbox":
            self._mod_helper(self.sandbox_entry.get_text(), self.sandbox_text_buffer,\
                            data[1], "sandbox")
            self.clear_entry(self.sandbox_entry, None, user_call=True)
        elif data[0] == "corrupt":
            self._mod_helper(self.corrupt_entry.get_text(), self.corrupt_text_buffer,\
                            data[1], "corrupt")
            self.clear_entry(self.corrupt_entry, None, user_call=True)

    def _mod_helper(self, ip, buff, mode, app):
        start, end = buff.get_bounds()
        current_view = buff.get_text(start, end, False)
        current_list = current_view.split()
        if mode == "add":
            if ip in current_list: return
            current_view += "\n" + ip
        elif mode == "remove":
            if ip not in current_list: return
            current_list.remove(ip)
            current_view = "".join(el + "\n" for el in current_list)
        buff.set_text(current_view)
	if app == "blacklist":
	    with open("commands", "a") as f:
		f.write("self._modify_blacklist(" + `ip` + "," + `mode` + ")\n")

    def clear_entry(self, entry, event, user_call=False):
        if user_call or event.type == Gdk.EventType.BUTTON_RELEASE:
            entry.set_text("")

    def packet_send(self, button, data):
        if data == "ping":
            self.add_history(self.ping_text_buffer)
	    self.send_command(None, "self.send_ping("+`self.ping_entry.get_text()` + ")\n")
        elif data == "tcp":
            self.add_history(self.tcp_text_buffer)

    #Todo: Add IPs we've pinged to the text window
    def add_history(self, buff):
	pass

    #Todo: Finish this
    def clear_history(self, button, data=None):
	pass

if __name__ == "__main__":
    def quitter(window, data):
	if window.controller:
		window.controller.terminate()
	Gtk.main_quit(window)

    win = SDNApp()
    win.connect("delete-event", quitter)
    win.initial_show()
    Gtk.main()
