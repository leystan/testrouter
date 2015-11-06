OVERVIEW OF CODE STRUCTURE:

The assignment can be easily split into two main parts, handling ARP packets and handling IP packets.
    
    ARP:
       - followed the outline defined in sr_arpcache.h to implement functions 
       - to handle ARP packets itself in sr_router.c required checking:
           ->validity of the ARP packets
	   ->checking the cache
	   ->add the necessary ethernet headers
	   ->determine if it is an ARP request -- create the necessary reply
	   
    IP: consisting of imcp and icmp type 3
        - somewhat similar to ARP, need to determine the different cases of handling the IP packet
	- may need to route the packet else where (decreasing its TTL) and adding the necessary ethernet
	  header before sending
	- when recieving an icmp packet need to determine its type in order to handle it (unreachable, TTL            exceeded, or an echo reply)
	    -> based on its type need to create an icmp or icmp type 3

	     
DESIGN DECISIONS:

Nothing out of the ordinary, just basic decisions to make things more clear.

   - defining different global variables in coresponding header files to make things clear/managable
     -> defining the default TTL
     -> defining the variables for the different icmp types
   - creating helper functions to check if the packets are valid
   - creating helper functions to handle the different cases for ARP packets and IP packet
	   
       	
        

