import unittest,struct
from capture import header
class Header(unittest.TestCase):
 def packet(self):
  b=bytearray(64);b[0]=0x45;b[9]=6;b[12:16]=bytes([10,0,0,1]);b[16:20]=bytes([198,18,0,2]);struct.pack_into('!H',b,2,64);struct.pack_into('!HHII',b,20,40000,9192,17,19);b[32]=0x50;b[33]=0x12;b[40:]=b'secret-payload-forbidden!';return b
 def test_no_payload(self):
  r=header(self.packet());self.assertEqual((r['sport'],r['dport'],r['seq'],r['ack'],r['flags']),(40000,9192,17,19,18));self.assertNotIn('secret',str(r))
 def test_reject(self):
  for mode in ['short','version','protocol','fragment','port','offset','length','tcplen']:
   b=self.packet()
   if mode=='short':b=b[:39]
   if mode=='version':b[0]=0x65
   if mode=='protocol':b[9]=17
   if mode=='fragment':b[7]=1
   if mode=='port':b[22:24]=b'\x00\x50'
   if mode=='offset':b[0]=0x41
   if mode=='length':b[2:4]=b'\x00\x19'
   if mode=='tcplen':b[32]=0x10
   with self.subTest(mode=mode):self.assertIsNone(header(b))
if __name__=='__main__':unittest.main()
