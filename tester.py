from firewall import Firewall


fw = Firewall("./rules.csv")

def test_1 ():

  assert fw.accept_packet("inbound", "tcp", 80, "192.168.1.2") # matches first rule

def test_2():
 
  assert fw.accept_packet("inbound", "udp", 53, "192.168.2.1") # matches third rule

def test_3():

  assert fw.accept_packet("outbound", "tcp", 10234, "192.168.10.11") # matches second rule true


def test_4():
  assert fw.accept_packet("inbound", "tcp", 81, "192.168.1.2") == False


def test_5():
  assert fw.accept_packet("inbound", "udp", 24, "52.12.48.92") == False

def test_6():
    assert fw.accept_packet("inbound", "udp", 53, "192.168.2.5") #matches third rule edge case

def test_7():
    assert fw.accept_packet("inbound", "udp", 53, "192.168.1.1") #matches third rule edge case


def test_8():
    assert fw.accept_packet("outbound", "tcp", 10000, "192.168.10.11") # matches second rule edge case

def test_9():
    assert fw.accept_packet("outbound", "tcp", 20000, "192.168.10.11") # matches second rule edge case

def test_10():
    assert  fw.accept_packet("outbound", "tcp", 80, "192.168.1.2") == False # does not match first rule by one field

def test_11():
    assert fw.accept_packet("inbound", "udp", 80, "192.168.1.2") == False # does not match first rule by one field

def test_12():
    assert fw.accept_packet("inbound", "tcp", 70, "192.168.1.2") == False # does not match first rule by one field

def test_13():
    assert fw.accept_packet("inbound", "tcp", 80, "192.168.1.3") == False # does not match first rule by one field



