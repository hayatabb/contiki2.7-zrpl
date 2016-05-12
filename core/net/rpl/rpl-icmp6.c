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
#include "lib/memb.h"
#include "sys/ctimer.h"
#include "sys/clock.h"
#include <stdio.h>
#include <stdlib.h>
#include "lib/random.h"
#include <limits.h>
#include <string.h>
#include "sys/node-id.h"


#define DEBUG 1//DEBUG_NONE

#include "net/uip-debug.h"

#if UIP_CONF_IPV6
/*---------------------------------------------------------------------------*/
#define UIP_IP_BUF       ((struct uip_ip_hdr *)&uip_buf[UIP_LLH_LEN])
#define UIP_ICMP_BUF     ((struct uip_icmp_hdr *)&uip_buf[uip_l2_l3_hdr_len])
#define UIP_ICMP_PAYLOAD ((unsigned char *)&uip_buf[uip_l2_l3_icmp_hdr_len])
/*---------------------------------------------------------------------------*/
#ifdef EDGE_ROUTER
uint16_t calcu_subnet_prefix(rpl_position_t destination_position);
int add_super_router_list(rpl_position_t *super_router_position);
int check_super_router_list(rpl_position_t *super_router_position);
void remove_super_router(rpl_position_t *super_router_position);
int edge_router_give_out_prefix(rpl_position_t *destination_position, uint8_t request_time);
MEMB(super_router_list_mem, struct super_router_list, 64);   // 64 super router at most  
#else
static struct ctimer dismiss_timer; 
void dismiss_subnet(void *ptr);    
int router_accept_prefix(rpl_position_t *node_position);
int router_give_out_prefix(rpl_position_t *node_position,int destination_goal);
#endif /*EDGE_ROUTER*/

uint8_t debug_test1 = 0;
uint8_t debug_test2 = 0;
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
  int prefix_request_time; //request time 

   uip_ipaddr_copy(&from, &UIP_IP_BUF->srcipaddr);
   /*
  PRINTF("RPL: Received a DIS from ");
  PRINT6ADDR(&from);
  PRINTF("\n");
				   */
  
  if((nbr = uip_ds6_nbr_lookup(&from)) == NULL)       
	  if((nbr = uip_ds6_nbr_add(&from, (uip_lladdr_t *)
								packetbuf_addr(PACKETBUF_ADDR_SENDER),
								0, NBR_REACHABLE)) != NULL) {
		  /* set reachable timer */
		  stimer_set(&nbr->reachable, UIP_ND6_REACHABLE_TIME / 1000);
		  /*
		  PRINTF("RPL: Neighbor added to neighbor cache ");
		  PRINT6ADDR(&from);
		  PRINTF(", ");
		  PRINT6ADDR((uip_lladdr_t *)packetbuf_addr(PACKETBUF_ADDR_SENDER));
		  PRINTF("\n");
					 */
	       }
  
  buffer = UIP_ICMP_PAYLOAD;  
  pos = 0;
  destination_goal = buffer[pos++];
  destination_position.x_axis = buffer[pos++];
  destination_position.y_axis = buffer[pos++];
  prefix_request_time = buffer[pos++];
#ifdef EDGE_ROUTER 
  if (destination_goal == RPL_ROUTER)
	  if (edge_router_give_out_prefix(&destination_position,prefix_request_time)){
	  if (add_super_router_list(&destination_position))
	               dio_output(&from,calcu_subnet_prefix(destination_position));
	  PRINTF("Send out prefix to ");
	  PRINT6ADDR(&from);
	  PRINTF("\n");
  }
#endif
#ifdef ROUTER
    if (uip_is_addr_equal(&my_info->my_address, &UIP_IP_BUF->destipaddr)){          //DIO reply
		if (destination_goal == RPL_LEAF) number_leaf++;
		      //TODO: add_leaf_to_route_table();
		else if (destination_goal == RPL_ROUTER) {
			number_node++;
			PRINTF("Subnet has %d nodes\n",number_node);
			//TODO: add_router_to_route_table();
		}
	}
	else  if (uip_is_addr_linklocal_rplnodes_mcast(&UIP_IP_BUF->destipaddr)){
		if ((prefix_request_time > REQUEST_TIME_MAX)||(router_give_out_prefix(&destination_position,destination_goal)))         //boardcast DIS 
		    dio_output(&from);	 	
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
  request_time++;
  PRINTF("request %d times\n",request_time);
  buffer[pos++] = request_time;
  if(addr == NULL) {
    uip_create_linklocal_rplnodes_mcast(&tmpaddr);
    addr = &tmpaddr;
  }
  /*
  PRINTF("RPL: Sending a DIS to ");
  PRINT6ADDR(addr);
  PRINTF("\n");
  */
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
  uint16_t incoming_prefix;
  uint8_t incoming_prefix_length;
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
	 if ((dismiss_prefix == my_info->my_prefix)&&(destination_goal == RPL_SUPER_ROUTER)){ 
	  PRINTF("Our subnet ");                           // TODO how to compare address
	  //PRINT6ADDR(&dismiss_prefix);
	  PRINTF(" is dismissed\n");
      memset(&my_info->my_prefix,0, my_info->prefix_length/8);
	  has_prefix = RPL_NO_PREFIX;
	  request_time = REQUEST_TIME_MAX - 1;
	  rpl_reset_periodic_timer();    
     }
      break;
#endif /*ifdef ROUTER*/
    case RPL_OPTION_PREFIX_INFO:
		if (has_prefix == RPL_NO_PREFIX){
	  destination_goal = buffer[pos] >>6;
      incoming_prefix_length = buffer[pos++] & 0x3F;   
      memcpy(&incoming_prefix,&buffer[pos], incoming_prefix_length/8);
	  pos += incoming_prefix_length/8;
	  destination_position.x_axis = buffer[pos++];
	  destination_position.y_axis = buffer[pos++];
      nodes = buffer[pos++];
#ifdef ROUTER	  
	  if (destination_goal == RPL_EDGE_ROUTER){
	       my_info->my_goal = RPL_SUPER_ROUTER;
		   has_prefix = RPL_HAS_PREFIX;
		   my_info->prefix_length = incoming_prefix_length;
		   memcpy(&my_info->my_prefix ,&incoming_prefix, incoming_prefix_length/8);
		   ctimer_set(&dismiss_timer, dismiss_interval*CLOCK_SECOND, dismiss_subnet,NULL);
	   }
	   if (destination_goal == RPL_SUPER_ROUTER)
		  if (router_accept_prefix (&destination_position)){                         //decide to join the subnet 
			   has_prefix = RPL_HAS_PREFIX;
			   my_info->prefix_length = incoming_prefix_length;
			   memcpy(&my_info->my_prefix ,&incoming_prefix, incoming_prefix_length/8);
		       dis_output(&UIP_IP_BUF->srcipaddr);
			   PRINTF("My_prefix is  %x\n",my_info->my_prefix);
		   }   
#endif /*ROUTER*/
#ifdef LEAF
				  has_prefix = RPL_HAS_PREFIX;
				  dis_output(&UIP_IP_BUF->srcipaddr);
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
  if (subnet_organ_timeout)                       //set DIO option info
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
	if(addr == NULL) {
		uip_create_linklocal_rplnodes_mcast(&tmpaddr);
		addr = &tmpaddr;
	}
	PRINTF("RPL: Sending prefix info in DIO for ");
    PRINT6ADDR(addr);       
    PRINTF("\n");
	
    uip_icmp6_send(addr, ICMP6_RPL, RPL_CODE_DIO, pos);
}
#ifdef EDGE_ROUTER
int
edge_router_give_out_prefix(rpl_position_t *destination_position, uint8_t request_time){
	uint16_t random;
	uint16_t threshold;
	
  if (!check_super_router_list(destination_position))              //There is already a super router in this zone
	  return 0;
  random = random_rand();
  switch (request_time) {
	  case 1 : threshold =  30000; break;
	  case 2 : threshold =  10000; break;
	  case 3 : threshold =  5000; break;
	  case 4 : threshold =  2500; break;
	  case 5 : threshold =  1000; break;
	  default : threshold = 0; break;
  }
  if (random > threshold)
      return 1;
  return 0;
  }
  uint16_t 
   calcu_subnet_prefix(rpl_position_t destination_position){               //Calculate prefix based on router position
	  uint16_t sendout_prefix;
	 memset(&sendout_prefix,0,sizeof(uint16_t));
	 sendout_prefix = (destination_position.x_axis<<8) + (destination_position.y_axis);
	 return sendout_prefix;
  }
  int
  add_super_router_list(rpl_position_t *super_router_position){                                // Add a new super router to the list
	  super_router_list_t *p = my_super_router_list;
	  struct super_router_list *new;
	  new = memb_alloc(&super_router_list_mem);
	  if (new != NULL) {
	  new->super_router_position.x_axis = super_router_position->x_axis;
	  new->super_router_position.y_axis = super_router_position->y_axis;
	  new->next = NULL;
	  while (p->next != NULL)
		  p=p->next;
	 p->next = new;
      return 1; }
      return 0;
  }
  int check_super_router_list(rpl_position_t *super_router_position){                     // Check whether there is already a super router in the zone
	  super_router_list_t *p;
	  uint8_t distance;                            // here Manhattan Distance is used to simplify calculation
	  p = my_super_router_list;
	  if (p->next == NULL) return 1;   // no super router yet
	  while (p->next!=NULL){
		  p=p->next;
		  distance = abs(super_router_position->x_axis - p->super_router_position.x_axis)+
					 abs(super_router_position->y_axis - p->super_router_position.y_axis);
		  if (distance < SUBNET_RADIUS)
			  return 0;
	  }
	  return 1;
  }
#endif
#ifdef ROUTER
int router_give_out_prefix(rpl_position_t *node_position,int destination_goal){
	uint8_t distance;                           // here Manhattan Distance is used to simplify calculation
	uint16_t index;
	uint8_t random_index;
	if(has_prefix) {
		switch (destination_goal) {
			case RPL_LEAF : return 1; break;    //TODO decision function
			case RPL_ROUTER: 
				 if (my_info->my_goal == RPL_SUPER_ROUTER) 
				 {
					 distance = abs(node_position->x_axis - my_info->my_position.x_axis)+
								abs(node_position->y_axis - my_info->my_position.y_axis);
					 if ((distance > SUBNET_RADIUS +10)||(number_node > SUBNET_MAX)) return 0;    // exceed threshold, refuse prefix request directly
					 index = distance*3/2 + 5*number_node;                                                                  //normalization, 3/2 * distance/25 + number_node/5
					 random_index = random_rand() % 64;
					 if (random_index > index) return 1; 
				 }
				 break;
			 default: return 0;break;
		}
	}
	return 0;
}
int router_accept_prefix(rpl_position_t *node_position){
    uint8_t distance;                           // here Manhattan Distance is used to simplify calculation
	uint16_t index;
	uint8_t random_index;
     
	distance = abs(node_position->x_axis - my_info->my_position.x_axis)+
			   abs(node_position->y_axis - my_info->my_position.y_axis);
	if (distance > SUBNET_RADIUS + 10) return 0;        // too far
	//if (request_time > REQUEST_TIME_MAX) request_time = 5;    //some selection when join subnet although there has been too many times for requesting
	index = 100 * request_time / (distance*6/5);
	random_index = random_rand() % 16;
	if (index > random_index) return 1;
	return 0;
}
void 
dismiss_subnet(void *ptr){
	if ((number_node< SUBNET_MIN)&&(my_info->my_goal == RPL_SUPER_ROUTER)){
		subnet_organ_timeout = 1;
	    dio_output(NULL);
		PRINTF("Dismiss_subnet");
	}
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
