from scapy.layers.l2 import ARP
from scapy.layers.l2 import Ether
from scapy.all import srp
import optparse

def get_args():
    parser=optparse.OptionParser()
    parser.add_option("-r","--range",dest="range",help="use -r to scan your local network")
    option= parser.parse_args()[0]
    if not option.range:
        parser.error("specify an option ")
    else:
        return option


def scan(ip):
    """""
    1)Making arp request (Who has some ip)
    2)setting destination for packet(For setting that Ether()is used)
       Destination is for reaching the packet
       Source is for resending(i.e,ARP Response)

    3)combining the two variables using(/)
    4)In order to understand the code execute the commented codes also
    """

    arp_request=ARP(pdst=ip)
    source_and_destination=Ether(dst="ff:ff:ff:ff:ff:ff")
    final=source_and_destination/arp_request
    #final.show()
    #print(final.summary())
   # answered_list,unanswered=srp(final,timeout=1,verbose=0)
    #Below line is a list.To print only the answerd_list we used [0] at the end
    answered_list= srp(final, timeout=1, verbose=0)[0]
    #print(answered.summary())
    result_list=[]
#Answered_list has list of lists
    for elements in answered_list:
# print(elements[1].show())
     #print(elements[1].psrc)
     #print(elements[1].hwsrc)
     #print(".....................................")
     result_dict={"ip":elements[1].psrc,"mac":elements[1].hwsrc}
     result_list.append(result_dict)
    return result_list

def print_list(result_list):
    print("ip\t\t\t\tmac")
    for each_result in result_list:
        print(each_result["ip"]+"\t\t"+each_result["mac"])

option=get_args()
result_dict=scan(option.range)
print_list(result_dict)