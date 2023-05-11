from pcie_pkt_checker import *
from tabulate import tabulate



print("Completion block")

completion = open('completion.txt', 'w')

class ep_completion_pkt(ep_base_pkt):
	def completion_fn(self, pkt_num):
    #temp=pkt_with_flag_queue
		pkts = pkt_with_flag_queue.queue[pkt_num]
		completion.write('priting packet{} from completer {}\n'.format(pkt_num, pkts))
		print('********************************* Valid Packet {} **********************************'.format(pkt_num))
		print('inherited valid packet is {}\n'.format(pkts))
	

		Fmt_f = pkts[0:3]

		
		if(int(Fmt_f[1], 2) == 1):
			Fmt = format(0, '03b')
		else:
			Fmt = format(2, '03b')
		Type = format(10, '05b')
		TC = pkts[9:12]
		Attr1 = pkts[13]
		TH = format(0, '01b')
		TD = pkts[16]
		EP = pkts[17]
		Attr0 = pkts[18:20]
		AT = format(0, '02b')
		Length = pkts[22:32]
		Attr = Attr1 + Attr0

		Completion_Id = pkts[64:80]
		if(pkts[-1] == '1'):
			Compl_status = format(3, '03b')
		else:
			Compl_status = format(0, '03b')
	#	Compl_status = format(0, '03b')
		BCM = format(0, '01b')
		Byte_count = format(int(Length, 2), '012b')

		Requester_Id = pkts[32:48]
		Tag = pkts[48:56]
		Lower_address = format(random.getrandbits(7), '07b')
		
		header = pkts[0:96]
		data = pkts[96:128]



		TLP = format(0, '0128b')   #default value is set to 128 bits
		TLP = Fmt + Type + format(0, '01b') + TC + format(0, '01b') + Attr1 + format(0, '01b') + TH + TD + EP + Attr0 + AT + Length + Completion_Id + Compl_status + BCM + Byte_count + Requester_Id + Tag + format(0, '01b') + Lower_address
	#	if((int(Fmt_l[1], 2) == 1) | (Compl_status == '001')):  #If either the Fmt field's second bit is 1 or the Compl_status field is '001', the TLP is extended with an additional 32 bits set to 0. Otherwise, the TLP is extended with a random binary string of 32 bits, where the number of bits is determined by the value of the Length field in the TLP.
		#	TLP = TLP + format(0, '032b')
	#	else:
		#	TLP = TLP + format(random.getrandbits(32 * (int(Length, 2))), '032b')
		if((int(Fmt_f[1], 2) == 1) | (pkts[-1] == '1')): 
			TLP = TLP + format(0, '032b')
		else:
			TLP = TLP + format(random.getrandbits(32 * (int(Length, 2))), '032b')
		
		data = [[ Fmt, Type, '', TC, '', Attr1, '', TH, TD, EP, Attr0, AT, Length, Completion_Id, Compl_status,BCM,Byte_count, Requester_Id,Tag,'',Lower_address,'']]
		headers = [ 'Fmt', 'Type', '', 'TC', '', 'Attr1', '', 'TH', 'TD', 'EP', 'Attr', 'AT', 'Length','Completion_Id', 'Compl_status', ' BCM' ,'Byte_count', 'Requester_Id', 'Tag', '', 'Lower_address', '']
		table = tabulate(data, headers=headers, tablefmt='orgtbl')
		completion.write(table)
	
		pkt_queue.put(TLP)

