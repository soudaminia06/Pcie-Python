from pcie_com_file import *
from tabulate import tabulate
from pcie_lib import * 

print("this is rc_check_pkt.py")
comp_send = open('completer_send.txt', 'w')
class pcie_rc_checker_pkt():
	def rc_checker_fn(self, pkt_num):
		valid_pkts = compl_pkt_queue.queue[pkt_num]
		comp_send.write('\n priting packet{} from completer\n' '{}\n'.format(pkt_num, valid_pkts))

		TLP_compl = valid_pkts
		Fmt = TLP_compl[0:3]
		Type = TLP_compl[3:8]
		TC = TLP_compl[9:12]
		Attr1 = TLP_compl[13]
		TH = TLP_compl[15]
		TD = TLP_compl[16]
		EP = TLP_compl[17]
		Attr0 = TLP_compl[18:20]
		AT = TLP_compl[20:22] 
		Length = TLP_compl[22:32] 

		Completion_Id = TLP_compl[32:48]
		Compl_status = TLP_compl[48:51]
		BCM = TLP_compl[51]
		Byte_count = TLP_compl[52:64]

		Requester_Id = TLP_compl[64:80]
		Tag = TLP_compl[80:88]
		Lower_address = TLP_compl[89:96]

		data = TLP_compl[96:128]
		
		
		Data = [[ Fmt, Type, '', TC, '', Attr1, '', TH, TD, EP, Attr0, AT, Length, Completion_Id, Compl_status,BCM,Byte_count, Requester_Id,Tag,'',Lower_address,'',data]]
		headers = [ 'Fmt', 'Type', '', 'TC', '', 'Attr1', '', 'TH', 'TD', 'EP', 'Attr', 'AT', 'Length','Completion_Id', 'Compl_status', ' BCM' ,'Byte_count', 'Requester_Id', 'Tag', '', 'Lower_address', '','data']
		table = tabulate(Data, headers=headers, tablefmt='orgtbl')
		comp_send.write(table)

		if Fmt in ['000', '010']:
			if(Type == '01010'):
				if(TC == '000'):
					if(Attr1 == '0'):
						if(TH == '0'):
							if(TD == '0'):
								if(EP == '0'):
									if(Attr0 == '00'):
										if(AT == '00'):
											if(int(Length, 2) == 1):
												if(BCM == '0'):
													if(Compl_status == '000'):
														if(Byte_count == format(int(Length, 2), '012b')):
															if((int(Fmt[1], 2) != 0) & (data == 0)):          # if the second bit in the Fmt string is equal to 0
																comp_send.write('\npacket is bad data\n')
															else:
																comp_send.write('\npacket is good data\n')
														else:
															comp_send.write('packet is bad byte count\n')
													else:
														comp_send.write('packet is bad compl_status\n')
												else:
													comp_send.write('packet is bad bcm\n')
											else:
												comp_send.write('packet is bad length\n')
										else:
											comp_send.write('packet is bad AT\n')
									else:
										comp_send.write('packet is bad Att0\n')
								else:
									comp_send.write('packet is bad EP\n')
							else:
								comp_send.write('packet is bad TD\n')
						else:
							comp_send.write('packet is bad TH\n')
					else:
						comp_send.write('packet is bad ATT1\n')
				else:
					comp_send.write('packet is bad TC\n')
			else:
				comp_send.write('packet is bad Type\n')
	

		

		
		
