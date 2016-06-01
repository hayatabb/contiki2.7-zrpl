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
 */
/**
 * \file
 *         RPL timer management.
 *
 * \author Joakim Eriksson <joakime@sics.se>, Nicolas Tsiftes <nvt@sics.se>
 */

#include "contiki-conf.h"
#include "net/rpl/rpl-private.h"
#include "lib/random.h"
#include "sys/ctimer.h"

#if UIP_CONF_IPV6

#define DEBUG DEBUG_NONE
#include "net/uip-debug.h"
uint8_t debug_test2 = 0;
/*---------------------------------------------------------------------------*/
static struct ctimer periodic_dis_timer;
static void handle_dis_periodic_timer(void *ptr);
#ifdef ROUTER
static struct ctimer periodic_dao_timer;
static void handle_dao_periodic_timer(void *ptr);
#endif
/*---------------------------------------------------------------------------*/
static void
handle_dis_periodic_timer(void *ptr)
{
  rpl_purge_routes();
#ifndef EDGE_ROUTER
  clock_time_t waiting;             // random waiting before send out first DIS
  waiting =  random_rand() % 45;   //waiting for 1-45 s randomly	
  if(has_prefix == RPL_NO_PREFIX) {
  dis_output(NULL);
  ctimer_set(&periodic_dis_timer,waiting*CLOCK_SECOND,
			handle_dis_periodic_timer,NULL);		
    }
#endif  /*EDGE_ROUTER*/
}
/*---------------------------------------------------------------------------*/
void
rpl_reset_dis_periodic_timer(void)        // Zuo 
{
  clock_time_t waiting;             // random waiting before send out first DIS
  waiting =  random_rand() % 30;   //waiting for 1-30 s randomly	
#ifdef LEAF
   waiting = waiting + 10;                      // leaves wait 180s until routers finished initializing
#endif /*LEAF*/
  debug_test2 = waiting;
  ctimer_set(&periodic_dis_timer, waiting*CLOCK_SECOND, handle_dis_periodic_timer, NULL);
}
/*---------------------------------------------------------------------------*/
#ifdef ROUTER
static void
handle_dao_periodic_timer(void *ptr)
{
	rpl_purge_routes();
	clock_time_t waiting;             // random waiting interval for sending dao
	waiting =  random_rand() % 30;   //waiting for 1-60 s randomly	
	if(has_prefix) {
		dao_output(NULL);
		ctimer_set(&periodic_dao_timer,waiting*CLOCK_SECOND,
				   handle_dao_periodic_timer,NULL);		
    }
}
/*---------------------------------------------------------------------------*/
void 
rpl_reset_dao_timer(void)
{
	clock_time_t waiting;             // random waiting before send out first DIS
	waiting =  240 + random_rand() % 30;   //waiting for 1-30 s randomly
	ctimer_set(&periodic_dao_timer, waiting*CLOCK_SECOND, handle_dao_periodic_timer, NULL);
}
#endif /*ROUTER*/
#endif /*UIP_CONF_IPV6*/
