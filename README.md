# FirewallImplementation

My initial, naive solution, which I got to be working code, was simply to insert each rule object into a list, finding a match between the inputted parameters and the rules by iterating through the list and find the first one that matches. However, this would take O(n) where n is the number of elements in the array since worst case, we have to iterate through all the elements in the array. 
However, I wanted to find a solution better than O(n). On the internet, while searching for more efficient ways to range query, I found the concept of interval trees at this website: https://pypi.org/project/intervaltree/ , which was a more efficient way to return all intervals matching a given point, which I used for the IP address range and the port range and filtered for the common rule in both sets.

This implementation uses an interval tree to easily match the inputted port and inputted IP address to the given ranges for the port and IP address in each rule, respectively. The insertion into an interval tree takes O(nlogn) to create the tree once and for each matching test, takes O(logn + k) where n is the number of intervals and k is the number of matches in the set. The space complexity of this solution is O(n).

I ran my tests using the pytest command with tester.py. My first five tests mimic the examples given in the prompt given the example file in the prompt. My next two tests are testing the edge cases of the third rule by inputting the IP Address value at both the lower and upper bound of the range specified in the third rule, which should return true. The next two tests similarly test the edge case for the second rule of my file by inputting the port value as both the lower and upper bound of the range in the second rule. The next four tests match rule one except for one field (either direction, protocol, IP address, or port) so they will return false.


To run the tests: 
pytest tester.py

To install pytest:
https://docs.pytest.org/en/latest/getting-started.html
 
