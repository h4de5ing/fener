
__VERSION__ = '0.1'
__AUTHOR__ = 'Galkan'
__DATE__ = '20.07.2014'


try:
	import os
	import re
	import sys
	import signal
	import tempfile
	import datetime
	import argparse
	import subprocess
	from lib.core.threadpool import Worker,ThreadPool
	from lib.core.config_parser import ConfigParser
	from lib.core.iprange import IpRange	
	from threading import Thread
	from lib.nmap import Nmap		
except ImportError,e:
        import sys
        sys.stdout.write("%s\n" %e)
        sys.exit(1)



class AddressAction(argparse.Action):
  
        def __call__(self, parser, args, values, option = None):
		
		args.options = values

		if args.scan_type == "active":
			if args.config is None:
				print >> sys.stderr, "usage: Usage: use --help for futher information\nfener.py: error: argument -c/--config is required"	
				sys.exit(1)
			elif args.target is None:	
				print >> sys.stderr, "usage: Usage: use --help for futher information\nfener.py: error: argument -t/--target is required"		
				sys.exit(1)
			
		elif args.scan_type == "screen": 
			if args.rasterize is None:
				print >> sys.stderr, "usage: Usage: use --help for futher information\nfener.py: error: argument -r/--rasterize is required"
				sys.exit(1)
			elif args.target is None:	
				print >> sys.stderr, "usage: Usage: use --help for futher information\nfener.py: error: argument -t/--target is required"		
				sys.exit(1)			

		elif args.scan_type == "passive": 
			if args.interface is None:
				print >> sys.stderr, "usage: Usage: use --help for futher information\nfener.py: error: argument -i/--interface is required"
				sys.exit(1)
			elif args.target is None:	
				print >> sys.stderr, "usage: Usage: use --help for futher information\nfener.py: error: argument -t/--target is required"		
				sys.exit(1)		
			


class Main:
		
	def __init__(self):
		
		self.tcpdump_path = "/usr/sbin/tcpdump"
		self.nmap_path = "/usr/bin/nmap"
		self.arpspoof_path = "/usr/sbin/arpspoof"
		self.phantomjs_path = "/usr/local/bin/phantomjs"
		self.tshark_path = "/usr/bin/tshark"

		self.services = {"active":self.active_scan,"passive":self.passive_scan,"filter":self.filter,"screen":self.screenshot}	

		description = "Fener: Ligth your ways throug pentest ..."
                usage = "Usage: use --help for futher information"
                parser = argparse.ArgumentParser(description = description, usage = usage)
                parser.add_argument('-s', '--scan_type', dest = 'scan_type', help = 'Passive Scan', choices = self.services.keys(), required = True)
		parser.add_argument('-p', '--project', dest = 'project', action = 'store', help = 'Project Name', required = True)
		parser.add_argument('-t', '--target', dest = 'target', action = 'store', help = 'Target Ip Address')		
		parser.add_argument('-c', '--config', dest = 'config', action = 'store', help = 'Configuration File')
		parser.add_argument('-i', '--interface', dest = 'interface', action = 'store', help = 'Interface')
		parser.add_argument('-r', '--rasterize', dest = 'rasterize', action = 'store', default = "/usr/local/bin/rasterize.js" ,help = 'Rasterize Js File For ScreenShot')
		parser.add_argument('-n', '--thread', dest = 'thread', action = 'store', help = 'Thread Number', default = 10, type = int)
		parser.add_argument('-l', '--log', dest = 'log_file', action = 'store', help = 'Log File', metavar = 'FILE', default = "fener.log")				
                parser.add_argument('-o', '--output', dest = 'output', action = 'store', help = 'Output File', metavar = 'FILE', default = "fener.out")		
		parser.add_argument('-d', '--passive_timeout', dest = 'passive_timeout', action = 'store', help = 'Passive Scan Timeout Value', default = 15, type = int)
		parser.add_argument('-m', '--mim', dest = 'mim', action = 'store', help = 'Man In The Middle')

		parser.add_argument('options', nargs='*', action = AddressAction)
		#parser.add_argument('--verbose', '-v', action = 'store', dest = 'verbose', type = int)

		try:
                	self.args = parser.parse_args()
		except Exception, err:
			print >> sys.stderr, err
			sys.exit(1)	
	
		for fener_file in self.args.log_file, self.args.output:
			if not os.path.exists(fener_file):
				open(fener_file, 'w').close()	
		
		self.fd_log_file = open(self.args.log_file, "a")
		self.fd_output_file = open(self.args.output, "a")

		now = datetime.datetime.now()
		start_time = "START TIME: " + now.strftime("%Y-%m-%d %H:%M:%S") + "\n"
		
		print start_time[:-1]
		self.fd_log_file.write(start_time)

		self.thread_list = []		
		self.ip_list = []
		try:
			iprange = IpRange()
			for ip in iprange.iprange(self.args.target):
				self.ip_list.append(ip)
		except:
			print >> sys.stderr, "Please use IP/CIDR notation. <192.168.37.37/32, 192.168.1.0/24>"
			sys.exit(1)
		
		self.output_dir = "output" + "/" + self.args.project
		if not os.path.isdir(self.output_dir):
			try:
				os.makedirs(self.output_dir)
			except Exception, err:
				print >> sys.sdterr, err
				sys.exit(1)

		if self.args.config is not None:
			self.cfg = ConfigParser.parse(self.args.config)
		

	
	def active_scan(self):

		""" Nmap Port Scan """
		
		self.nmap = Nmap(self.nmap_path, self.output_dir, self.args.thread)
	
		ports = self.cfg["scan"]
		script = self.cfg["script"]

		alive_hosts = self.nmap.ping_scan(self.args.target)
		try:
			t1 = Thread(target = self.nmap.os_scan, args = (alive_hosts,))
			t1.start()
			self.thread_list.append(t1)
			
			t2 = Thread(target = self.nmap.port_service_scan, args = (alive_hosts, ports,))	
			t2.start()	
			self.thread_list.append(t2)

			t3 = Thread(target = self.nmap.script_scan, args = (alive_hosts, script, ports,))
			t3.start()
			self.thread_list.append(t3)
		except Exception, err:
			print >> sys.stderr, err
			sys.exit(1)

		for t in self.thread_list:
			t.join()
		
		alive_hosts.close()

		sys.exit(0)
	

	def run_phantomjs(self, cmd_opt):

		""" Run Phantomjs in order to take screenshot """

		proc = subprocess.Popen([cmd_opt], shell=True, stdout=subprocess.PIPE,)
                stdout_value = str(proc.communicate())


	def screenshot(self):
		
		""" Take ScreenShot """
		
		for rasterize_file in self.phantomjs_path, self.args.rasterize:
			if not os.path.exists(rasterize_file):
				print >> sys.stderr, "%s Doesn't Exists On The System !!!"% rasterize_file
				sys.exit(1)
			
		screen_output_dir = self.output_dir + "/screen/"
		if not os.path.isdir(screen_output_dir):
			try:
				os.makedirs(screen_output_dir)
			except Exception, err:
				print >> sys.sdterr, err
				sys.exit(1)

		now = datetime.datetime.now()
		screen_time = now.strftime("%Y%m%d%H%M") 
		
		if not screen_output_dir[0] == "/":
			screen_output_dir = os.getcwd() + "/" + screen_output_dir

		http_reg = re.compile("80/open/tcp//")
        	https_reg = re.compile("443/open/tcp//")
   
		http_list = []
		https_list = []
		url_list = []	

		tmp = tempfile.NamedTemporaryFile(mode='w+t')
		tmp_file = tmp.name

		nmap_scan_option = "-n -Pn -T4 -sT -p 80,443 --open --host-timeout=10m --max-rtt-timeout=600ms --initial-rtt-timeout=300ms --min-rtt-timeout=300ms --max-retries=2 --min-rate=150 %s -oG %s"% (self.args.target, tmp_file)
				
		run_nmap = "%s %s"% (self.nmap_path, nmap_scan_option)
		
		proc = subprocess.Popen([run_nmap], shell=True, stdout=subprocess.PIPE,)
                stdout_value = str(proc.communicate())
		
		for line in tmp:
			if re.search(http_reg, line):
				ip = line.split()[1]				
				http_list.append(ip)

			if re.search(https_reg, line):
				ip = line.split()[1]				
				https_list.append(ip)

		for host in http_list:
			url = "http://%s"% (host)
			url_list.append(url)

		for host in https_list:
			url = "https://%s"% (host)
			url_list.append(url)
			
		tmp.close()

		pool = ThreadPool(self.args.thread)
		for url in url_list:
			output_file = screen_output_dir + url.split(":")[0] + "-" + url.split("/")[2] + "_" + screen_time + ".png"	
			phantomjs_cmd = "%s --ignore-ssl-errors=yes %s %s %s"% (self.phantomjs_path, self.args.rasterize, url, output_file)		
			pool.add_task(self.run_phantomjs, phantomjs_cmd)			

		pool.wait_completion()
		


	def passive_scan(self):

		""" Run tcpdump to sniff network traffic """

		proc = subprocess.Popen([self.tcpdump_path,"-tttnn","-i",self.args.interface,"-s", "0", "-w", "kaydetp.pcap"] , stdout=subprocess.PIPE,)
                stdout_value = str(proc.communicate())

		
	def arpspoof(self):
		pass
	
	def filter(self):
		pass
	

	def run(self, scan_type):
	
		signal.signal(signal.SIGINT, self.signal_handler)
		
		if not scan_type in self.services.keys():
			print >> sys.stderr, "%s is not valid service. Please select %s "% (scan_type, self.services.keys())
			sys.exit(1)
		else:
			self.services[scan_type]()


	def signal_handler(self, signal, frame):

		print('Bye ...')
         	sys.exit(37)	

