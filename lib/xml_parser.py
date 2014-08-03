#!/usr/bin/python

__VERSION__ = '0.1'
__AUTHOR__ = 'Galkan'
__DATE__ = '20.07.2014'


try:
	import sys
	import xml.dom.minidom
except ImportError,e:
        import sys
        sys.stdout.write("%s\n" %e)
        sys.exit(1)


class XmlParser:
	
	result = []

	@staticmethod
	def parser(xml_file):
		
		print xml_file
		if not XmlParser.result:
			try:
                		root = xml.dom.minidom.parse(xml_file) 		
			except Exception, err:
				print >> sys.stderr, err
				sys.exit(1)

		
		for host in root.getElementsByTagName("host"):

			try:
                		address = host.getElementsByTagName("address")[0]
                		ip = address.getAttribute("addr")
                		protocol = address.getAttribute("addrtype")
            		except:
				pass


			try:
                		os = host.getElementsByTagName("os")[0]
                		os_match = os.getElementsByTagName("osmatch")[0]
                		os_name = os_match.getAttribute("name")
                		os_accuracy = os_match.getAttribute("accuracy")
                		os_class = os.getElementsByTagName("osclass")[0]
                		os_family = os_class.getAttribute("osfamily")
                		os_gen = os_class.getAttribute("osgen")
            		except:
                		os_name = ""
                		os_accuracy = ""
                		os_family = ""
                		os_gen = ""
			
			ret = ip + ":" + os_family + ":" + os_name
			XmlParser.result.append(ret)

		print XmlParser.result


##
### Main ...
##


if __name__ == "__main__":
	
	xml_parser = XmlParser(sys.argv[1])
	xml_parser.parser()
