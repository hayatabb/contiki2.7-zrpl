/**
 * \addtogroup uip6
 * @{
 */
/*
 * Copyright (c) 2010, Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is part of the Contiki operating system.
 *
 */
/**
 * \file
 *         ICMP6 I/O for RPL control messages.
 *
 * \author Joakim Eriksson <joakime@sics.se>, Nicolas Tsiftes <nvt@sics.se>
 * Contributors: Niclas Finne <nfi@sics.se>, Joel Hoglund <joel@sics.se>,
 *               Mathieu Pouillot <m.pouillot@watteco.com>
 */

#include "net/tcpip.h"
#include "net/uip.h"
#include "net/uip-ds6.h"
#include "net/uip-nd6.h"
#include "net/uip-icmp6.h"
#include "net/rpl/rpl-private.h"
#include "net/rpl/rpl.h"
#include "net/packetbuf.h"
#include "lib/random.h"
#include "sys/ctimer.h"
#include <stdio.h>
#include <stdlib.h>

#include <limits.h>
#include <string.h>
#include "sys/node-id.h"


#define DEBUG DEBUG_NONE

#include "net/uip-debug.h"

#if UIP_CONF_IPV6
/*---------------------------------------------------------------------------*/
#define UIP_IP_BUF       ((struct uip_ip_hdr *)&uip_buf[UIP_LLH_LEN])
#define UIP_ICMP_BUF     ((struct uip_icmp_hdr *)&uip_buf[uip_l2_l3_hdr_len])
#define UIP_ICMP_PAYLOAD ((unsigned char *)&uip_buf[uip_l2_l3_icmp_hdr_len])
/*---------------------------------------------------------------------------*/
//extern	rpl_selfinfo_t *my_info;
uint16_t calcu_subnet_prefix(rpl_position_t destination_position);


/*---------------------------------------------------------------------------*/
static int
get_global_addr(uip_ipaddr_t *addr)
{
  int i;
  int state;

  for(i = 0; i < UIP_DS6_ADDR_NB; i++) {
    state = uip_ds6_if.addr_list[i].state;
    if(uip_ds6_if.addr_list[i].isused &&
       (state == ADDR_TENTATIVE || state == ADDR_PREFERRED)) {
      if(!uip_is_addr_link_local(&uip_ds6_if.addr_list[i].ipaddr)) {
        memcpy(addr, &uip_ds6_if.addr_list[i].ipaddr, sizeof(uip_ipaddr_t));
        return 1;
      }
    }
  }
  return 0;
}
/*---------------------------------------------------------------------------*/
static uint32_t
get32(uint8_t *buffer, int pos)
{
  return (uint32_t)buffer[pos] << 24 | (uint32_t)buffer[pos + 1] << 16 |
         (uint32_t)buffer[pos + 2] << 8 | buffer[pos + 3];
}
/*---------------------------------------------------------------------------*/
static void
set32(uint8_t *buffer, int pos, uint32_t value)
{
  buffer[pos++] = value >> 24;
  buffer[pos++] = (value >> 16) & 0xff;
  buffer[pos++] = (value >> 8) & 0xff;
  buffer[pos++] = value & 0xff;
}
/*---------------------------------------------------------------------------*/
static uint16_t
get16(uint8_t *buffer, int pos)
{
  return (uint16_t)buffer[pos] << 8 | buffer[pos + 1];
}
/*---------------------------------------------------------------------------*/
static void
set16(uint8_t *buffer, int pos, uint16_t value)
{
  buffer[pos++] = value >> 8;
  buffer[pos++] = value & 0xff;
}
/*---------------------------------------------------------------------------*/
void
dis_input(void)    // finished
{
  unsigned char *buffer;
  int pos;
  uip_ipaddr_t from;
  uip_ds6_nbr_t *nbr;
  int destination_goal;
  rpl_position_t destination_position;
  
   uip_ipaddr_copy(&from, &UIP_IP_BUF->srcipaddr);
  PRINTF("RPL: Received a DIS from ");
  PRINT6ADDR(&from);
  PRINTF("\n");
  
  if((nbr = uip_ds6_nbr_lookup(&from)) == NULL)       
	  if((nbr = uip_ds6_nbr_add(&from, (uip_lladdr_t *)
								packetbuf_addr(PACKETBUF_ADDR_SENDER),
								0, NBR_REACHABLE)) != NULL) {
		  /* set reachable timer */
		  stimer_set(&nbr->reachable, UIP_ND6_REACHABLE_TIME / 1000);
		  PRINTF("RPL: Neighbor added to neighbor cache ");
		  PRINT6ADDR(&from);
		  PRINTF(", ");
		  PRINT6ADDR((uip_lladdr_t *)packetbuf_addr(PACKETBUF_ADDR_SENDER));
		  PRINTF("\n");
	       }
  
  buffer = UIP_ICMP_PAYLOAD;  
  pos = 0;
  destination_goal = buffer[pos++];
  destination_position.x_axis = buffer[pos++];
  destination_position.y_axis = buffer[pos++];
  //destination_position.z_axis = buffer[pos++];
  request_time = buffer[pos++];
  //TODO: add checksum 
#ifdef EDGE_ROUTER 
  if (destination_goal == RPL_ROUTER){
	  //if (edge_router_give_out_prefix(destination_position,request_time)){  //TODO edge_router_give_out_prefix()
	  dio_output(&from,calcu_subnet_prefix(destination_position));
	  PRINTF("Send out prefix to ");
	  PRINT6ADDR(&from);
	  PRINTF("\n");
      //add_to_super_router_table(&destination_position, UIP_IP_BUF->srcipaddr); Zuo 
  }
#endif
#ifdef ROUTER
  if (destination_goal == RPL_LEAF) 
    //if (router_give_out_prefix(request_time)&&(has_prefix == RPL_HAS_PREFIX)){  Zuo
	  if (has_prefix == RPL_HAS_PREFIX){
	  dio_output(&from);
	  PRINTF("Send out prefix to ");
	  PRINT6ADDR(&from);
	  PRINTF("\n");
	  //add_leaf_to_router_table();
	  number_leaf++;
  }
if ((my_info->my_goal == RPL_SUPER_ROUTER)&&(destination_goal == RPL_ROUTER)){
		//&&(uip_is_prefix_equal(&my_info->my_address, &from))){// get a resopnse of last uni DIO  ??
		  PRINTF("Send out prefix to ");
		  PRINT6ADDR(&from);
		  PRINTF("\n");
		  number_node++;
	  } 	  
#endif
}
/*---------------------------------------------------------------------------*/
void
dis_output(uip_ipaddr_t *addr)    
{
  unsigned char *buffer;
  uip_ipaddr_t tmpaddr;
  int pos;
#ifdef EDGE_ROUTER
  request_time = 0;          //just for compiling
#endif

  /*       */
  /*      0                   1                   2        */
  /*      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3  */
  /*     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
  /*     |     Flags     |   Reserved    |   Option(s)...  */
  /*     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */

  buffer = UIP_ICMP_PAYLOAD;
  pos = 0;
  
  buffer[pos++] = my_info->my_goal;
  buffer[pos++] = my_info->my_position.x_axis;
  buffer[pos++] = my_info->my_position.y_axis;
  //buffer[pos++] = my_info->my_position.z_axis;
  buffer[pos++] = request_time;
  if(addr == NULL) {
    uip_create_linklocal_rplnodes_mcast(&tmpaddr);
    addr = &tmpaddr;
  }
  PRINTF("RPL: Sending a DIS to ");
  PRINT6ADDR(addr);
  PRINTF("\n");
  uip_icmp6_send(addr, ICMP6_RPL, RPL_CODE_DIS, pos);
}
/*---------------------------------------------------------------------------*/
void
dio_input(void)               
{
#ifndef EDGE_ROUTER
  unsigned char *buffer;
  int pos;
  uip_ipaddr_t from;
  uip_ds6_nbr_t *nbr;
  uint8_t subopt_type;
  uint8_t nodes;            //number of nodes for the incoming subnet
  int destination_goal;
  rpl_position_t destination_position;
  uint8_t dismiss_prefix_length;
  uint16_t dismiss_prefix;
  struct ctimer dismiss_timer; 
  uint8_t dismiss_interval;

  uip_ipaddr_copy(&from, &UIP_IP_BUF->srcipaddr);
  PRINTF("RPL: Received a DIO from ");
  PRINT6ADDR(&from);
  PRINTF("\n");
 
  if((nbr = uip_ds6_nbr_lookup(&from)) == NULL) {         
	  if((nbr = uip_ds6_nbr_add(&from, (uip_lladdr_t *)
								packetbuf_addr(PACKETBUF_ADDR_SENDER),
								0, NBR_REACHABLE)) != NULL) {
		  /* set reachable timer */
		  stimer_set(&nbr->reachable, UIP_ND6_REACHABLE_TIME / 1000);
		  PRINTF("RPL: Neighbor added to neighbor cache ");
		  PRINT6ADDR(&from);
		  PRINTF(", ");
		  PRINT6ADDR((uip_lladdr_t *)packetbuf_addr(PACKETBUF_ADDR_SENDER));
		  PRINTF("\n");
	     }
     }
  //buffer_length = uip_len - uip_l3_icmp_hdr_len;  
  pos = 0;
  buffer = UIP_ICMP_PAYLOAD;
  dismiss_interval = RPL_DISMISS_INTERVAL;          // dismiss timer

  /* Check DIO suboptions. */ 
   subopt_type = buffer[pos++];
   switch(subopt_type) {
#ifdef ROUTER
    case RPL_OPTION_SUBNET_TIMEOUT:   //dismiss subnet
	 destination_goal = buffer[pos] >>6;
	 dismiss_prefix_length = buffer[pos++] & 0x3F;
	 memcpy(&dismiss_prefix, &buffer[pos], dismiss_prefix_length/8);
	 if ((dismiss_prefix^my_info->my_prefix == 0x007F)&&(destination_goal == RPL_SUPER_ROUTER)){ 
	  PRINTF("Our subnet ");                           // TODO how to compare address
	  //PRINT6ADDR(&dismiss_prefix);
	  PRINTF(" is dismissed\n");
      memset(&my_info->my_prefix,0, my_info->prefix_length/8);
	  has_prefix = RPL_NO_PREFIX;
     }
      break;
#endif /*ifdef ROUTER*/
    case RPL_OPTION_PREFIX_INFO:
		if (has_prefix == RPL_NO_PREFIX){
	  destination_goal = buffer[pos] >>6;
      my_info->prefix_length = buffer[pos++] & 0x3F;   
      memcpy(&my_info->my_prefix, &buffer[pos], my_info->prefix_length/8);
	  PRINTF("RPL: Copying prefix information ");  
	  PRINT6ADDR(&my_info->my_prefix);
	  PRINTF("\n");
	  pos += my_info->prefix_length/8;
	  destination_position.x_axis = buffer[pos++];
	  destination_position.y_axis = buffer[pos++];
	  //destination_position.z_axis = buffer[pos++];
      nodes = buffer[pos++];
#ifdef ROUTER	  
	  if (destination_goal == RPL_EDGE_ROUTER){
	       my_info->my_goal = RPL_SUPER_ROUTER;
		   ctimer_set(&dismiss_timer, dismiss_interval*CLOCK_SECOND, dismiss_subnet,NULL);
	   }
	   if (destination_goal == RPL_SUPER_ROUTER)
		  if (in_my_range(&destination_position)&&(nodes<SUBNET_MAX)){  //decide to join the subnet
			   has_prefix = RPL_HAS_PREFIX;
		       dis_output(&UIP_IP_BUF->srcipaddr);
		   }
			   else { has_prefix = RPL_NO_PREFIX;        //refuse to join the subnet
			   memset(&my_info->my_prefix,0,my_info->prefix_length/8) ;  //set prefix to 0 again
			   my_info->prefix_length = 0;                            //set prefix_length to 0 again
		   }
#endif /*ROUTER*/
#ifdef LEAF
		  if (in_my_range(&destination_position)&&nodes<MAX_LEAF_NUMBER){  //decide to join the subnet
					  has_prefix = RPL_HAS_PREFIX;
				  dis_output(&UIP_IP_BUF->srcipaddr);}
					  else { has_prefix = RPL_NO_PREFIX;
				      memset(&my_info->my_prefix,0,my_info->prefix_length);   //set prefix to 0 again
				      my_info->prefix_length = 0;                            //set prefix_length to 0 again
			      }
#endif	  /*ifdef LEAF*/
			  }
      break;
    default:
      PRINTF("RPL: Unsupported suboption type in DIO: %u\n",
	(unsigned)subopt_type);
   }
   #endif  /*ifndef EDGE_ROUTER*/
}
/*---------------------------------------------------------------------------*/
void
#ifdef EDGE_ROUTER
dio_output(uip_ipaddr_t *addr, uint16_t prefix)     //finished
#else
dio_output(uip_ipaddr_t *addr)
#endif //ifdef EDGE_ROUTER
{
  unsigned char *buffer;
  int pos;
  uint8_t subopt_type;
  pos = 0;
  uip_ipaddr_t tmpaddr;
  buffer = UIP_ICMP_PAYLOAD;
#ifdef ROUTER
  if (subnet_organ_timeout)                        //set DIO option info
	  buffer[pos++] = RPL_OPTION_SUBNET_TIMEOUT;
  else 
#endif
      buffer[pos++] = RPL_OPTION_PREFIX_INFO;
  
  if (my_info->my_goal == RPL_EDGE_ROUTER)         //set goal info
	buffer[pos++] = (RPL_EDGE_ROUTER <<6)| my_info->prefix_length;
        else if (my_info->my_goal == RPL_SUPER_ROUTER)
	    buffer[pos++] = (RPL_SUPER_ROUTER <<6)| my_info->prefix_length;
	         else if (my_info->my_goal == RPL_ROUTER)
				 buffer[pos++] = (RPL_ROUTER <<6)| my_info->prefix_length;

	memset(&buffer[pos], 0, sizeof(my_info->my_prefix));   // set prefix info
#ifdef EDGE_ROUTER
	memcpy(&buffer[pos], &prefix, sizeof(my_info->my_prefix)); 
#else
	memcpy(&buffer[pos], &my_info->my_prefix, sizeof(my_info->my_prefix)); 
#endif
	pos += sizeof(my_info->my_prefix);
    buffer[pos++] = my_info->my_position.x_axis;         // set position info
	buffer[pos++] = my_info->my_position.y_axis;
	//buffer[pos++] = my_info->my_position.z_axis;
#ifdef ROUTER
    buffer[pos++] = number_node;                        // set node number info
#endif
	
	//TODO: checksum uint8_t
    PRINTF("RPL: Sending prefix info in DIO for ");
    PRINT6ADDR(addr);       
    PRINTF("\n");
	
	if(addr == NULL) {
		uip_create_linklocal_rplnodes_mcast(&tmpaddr);
		addr = &tmpaddr;
	}
    uip_icmp6_send(addr, ICMP6_RPL, RPL_CODE_DIO, pos);
}
#ifdef EDGE_ROUTER
int
edge_router_give_out_prefix(rpl_position_t destination_position, uint8_t request_time){
  //int more_than_radius;
  //more_than_radius = edge_router_check_route_table (&destination_position);  //Zuo
  //if (!more_than_radius) return 0;
  //TODO add some statistics function related to request time
  return 1;
  }
  uint16_t calcu_subnet_prefix(rpl_position_t destination_position){
	  uint16_t sendout_prefix;
	 memset(&sendout_prefix,0,sizeof(uint16_t));
	 sendout_prefix = (destination_position.y_axis<<8) + (destination_position.x_axis);
	 return sendout_prefix;
  }
#endif

int in_my_range(rpl_position_t *node_position){
	uint8_t distance;                           // here Manhattan Distance is used to simplify calculation
	distance = abs(node_position->x_axis - my_info->my_position.x_axis)+
			    abs(node_position->y_axis - my_info->my_position.y_axis);
	 if (distance < SUBNET_RADIUS)
		 return 1;
	 else
		 return 0;
}
#ifdef ROUTER
void 
dismiss_subnet(void *ptr){
	if ((number_node< SUBNET_MIN)&&(my_info->my_goal == RPL_SUPER_ROUTER))
		subnet_organ_timeout = 1;
	    dio_output(NULL);
  }
#endif  

void
uip_rpl_input(void)
{
  PRINTF("Received an RPL control message\n");
  switch(UIP_ICMP_BUF->icode) {
  case RPL_CODE_DIO:
	//if (my_info->my_goal != RPL_EDGE_ROUTER)            //edge router do not nedd to recevie dio
    dio_input();
    break;
  case RPL_CODE_DIS:
	//if (my_info->my_goal != RPL_LEAF)                  //leaf do not need to receive dis
    dis_input();
    break;
  default:
    PRINTF("RPL: received an unknown ICMP6 code (%u)\n", UIP_ICMP_BUF->icode);
    break;
    }
  uip_len = 0;
}

#endif /* UIP_CONF_IPV6 */