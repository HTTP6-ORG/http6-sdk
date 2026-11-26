import unittest
from http6_sdk import canonical, PilotClient, Response, VerificationError
class TestSDK(unittest.TestCase):
    def test_codec(self):
        self.assertEqual(canonical({'b':2,'a':['x',True]}),b'{"a":["x",true],"b":2}')
        for x in (-1,1.5,'\n',{'x':'é'}):
            with self.assertRaises(TypeError):canonical(x)
    def test_rejects_missing_pins_before_reading_evidence(self):
        c=PilotClient('agent','ledger','unused')
        with self.assertRaises(VerificationError):c.verify_response(Response(200,{},b''),'missing','bad','0'*64,'op')
        with self.assertRaises(VerificationError):c.verify_ledger([], 'bad')
if __name__=='__main__':unittest.main()
