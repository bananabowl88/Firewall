from intervaltree import Interval, IntervalTree

import csv

#given a string IP address, this function returns the 32-bit integer equivalent
def ipToInt(address):

    firstOctet, secondOctet, thirdOctet, fourthOctet = address.split(".")
    firstOctet = int(firstOctet)
    secondOctet = int(secondOctet)
    thirdOctet = int(thirdOctet)
    fourthOctet = int(fourthOctet)

    numAddress = (firstOctet * (256**3)) + (secondOctet * (256**2)) + (thirdOctet * 256) + fourthOctet

    return numAddress

#given a string address range, this function extracts the minimum and maximum IP address and calls the ipToInt function
# returns tuple of integer minimum and maximum IP address
def getMinMaxAddress(addressRange):
    if '-' not in addressRange:
      minAddress = addressRange
      maxAddress = addressRange
    else:
      minAddress, maxAddress = addressRange.split("-")

    minAddressInt = ipToInt(minAddress)
   # print(minAddressInt)

    maxAddressInt = ipToInt(maxAddress)

    return (minAddressInt, maxAddressInt)
 
 

#extracts the minimum and maximum port strings
#returns tuple of integer minimum and maximum port values
def getMinMaxPort(portRange):
    if "-" not in portRange:
      minPort = portRange
      maxPort = portRange
    else:
      minPort, maxPort = portRange.split("-")
    return (int(minPort), int(maxPort))

 
#instantiates Rule class where each line in the input file represents one rule
class Rule:

  def __init__(self, direction, protocol, minPort, maxPort, minIpAddress, maxIpAddress):
    self.direction = direction
    self.protocol = protocol
    self.minPort = minPort
    self.maxPort = maxPort
    self.minIpAddress = minIpAddress
    self.maxIpAddress = maxIpAddress

  def __repr__(self):
    return self.direction + "," + self.protocol + "," + str(self.minPort) + "," + str(self.maxPort) + "," + str(self.minIpAddress) + "," + str(self.maxIpAddress)

class Firewall:

  tPorts = IntervalTree()
  tAddresses = IntervalTree()


  def __init__(self, pathToFile):
    with open(pathToFile) as csvFile:
      readCsv = csv.reader(csvFile, delimiter = ',')

      for row in readCsv:
        rule = self.makeRule(row)

  #creates a rule object consisting of the direction, protocol, minimum port value, maximum port value, minimum address, and maximum address
  def makeRule(self, row):
        minPort, maxPort = getMinMaxPort(row[2])

        minAddress, maxAddress = getMinMaxAddress(row[3])

        rule =  Rule(row[0], row[1], minPort, maxPort, minAddress, maxAddress)

        #+1 due to closed interval on the right 
        self.tPorts[minPort:maxPort+1] = rule
        self.tAddresses[minAddress:maxAddress + 1] = rule

        return rule

  #returns True if there exists a common rule between the matchPorts set and matchAddresses set and if the direction and protocol match given parameters
  def checkIfCommonRule(self, matchPorts, matchAddresses, direction, protocol):

    portsLen = len(matchPorts)
    addressLen = len(matchAddresses)

    if portsLen < addressLen:
      for rule in matchPorts:
        if rule in matchAddresses:
          if rule.direction == direction and rule.protocol == protocol:
            return True
    
    else:
      for rule in matchAddresses:
        if rule in matchPorts:
          if rule.direction == direction and rule.protocol == protocol:
            return True

    return False
    

  #returns true if there exists a rule in file that allows for traffic
  def accept_packet(self, direction, protocol, port, ip_address):

      ipInt = ipToInt(ip_address)
      
      
      matchPortsInterval = self.tPorts[port]

      #creates set from the interval 
      matchPorts  = [ i.data for i in matchPortsInterval]
      matchAddressesInterval  = self.tAddresses[ipInt]
      matchAddresses  = [ i.data for i in matchAddressesInterval]

      return self.checkIfCommonRule(matchPorts, matchAddresses, direction, protocol)



