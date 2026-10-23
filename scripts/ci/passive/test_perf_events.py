import struct
import unittest
from perf_events import decode_sample, layouts, take_records


class ParserTests(unittest.TestCase):
    def test_runtime_offsets_and_signed_return(self):
        fields=layouts('field:long ret; offset:16; size:8; signed:1;',('ret',))
        raw=bytes(16)+struct.pack('<q',-115)
        sample=struct.pack('<IIQIII',123,125,555,1,0,len(raw))+raw
        self.assertEqual(decode_sample(sample,fields),{'pid':123,'tid':125,'at_ns':555,'cpu':1,'ret':-115})

    def test_address_byte_order(self):
        sample=struct.pack('<IIQIII',1,2,3,0,0,4)+bytes([127,0,0,1])
        self.assertEqual(decode_sample(sample,{'saddr':(0,4,False)})['saddr'],'127.0.0.1')

    def test_ring_wrap(self):
        record=struct.pack('<IHHQ',9,0,16,42)
        ring=bytearray(32)
        ring[28:]=record[:4];ring[:12]=record[4:]
        self.assertEqual(list(take_records(ring,28,44)),[(9,struct.pack('<Q',42))])

    def test_lost_record_is_preserved(self):
        record=struct.pack('<IHHQQ',2,0,24,100,4)
        self.assertEqual(list(take_records(record+bytes(8),0,24)),[(2,struct.pack('<QQ',100,4))])

    def test_invalid_ring_and_truncated_record_rejected(self):
        for ring,tail,head in [(bytes(16),0,17),(bytes(16),1,0),
                               (struct.pack('<IHHQ',9,0,24,1),0,16),
                               (struct.pack('<IHHQ',9,0,0,1),0,16)]:
            with self.subTest(head=head),self.assertRaises(ValueError):list(take_records(ring,tail,head))

    def test_missing_layout_or_truncated_payload_rejected(self):
        with self.assertRaises(ValueError):layouts('',('fd',))
        with self.assertRaises(ValueError):decode_sample(bytes(27),{})
        with self.assertRaises(ValueError):decode_sample(struct.pack('<IIQIII',1,2,3,0,0,8),{})
        with self.assertRaises(ValueError):decode_sample(struct.pack('<IIQIII',1,2,3,0,0,0),{'fd':(16,8,False)})


if __name__=='__main__':unittest.main()
