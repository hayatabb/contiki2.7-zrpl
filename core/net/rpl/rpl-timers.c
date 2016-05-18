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

/*---------------------------------------------------------------------------*/
static struct ctimer periodic_dis_timer;
static void handle_periodic_timer(void *ptr);
#ifdef ROUTER
static struct ctimer periodic_dior_timer;
static void handle_dior_timer(void *ptr);
#endif
/* dio_send_ok is true if the node is ready to send DIOs */
static uint8_t dio_send_ok;

/*---------------------------------------------------------------------------*/
static void
handle_periodic_timer(void *ptr)
{
  rpl_purge_routes();
#ifndef EDGE_ROUTER
  clock_time_t waiting;             // random waiting before send out first DIS
  waiting =  random_rand() % 45;   //waiting for 1-45 s randomly	
  if(has_prefix == RPL_NO_PREFIX) {
  dis_output(NULL);
  ctimer_set(&periodic_dis_timer,waiting*CLOCK_SECOND,
			handle_periodic_timer,NULL);		
    }
#endif
}
/*---------------------------------------------------------------------------*/
#ifdef ROUTER
static void
handle_dior_timer(void *ptr)
{
	uint16_t *last_waiting;             // increasint interval for sending DIO
	uint16_t  waiting;
	last_waiting = (uint16_t *)ptr;
	waiting = *last_waiting;
	if (waiting < 100) *last_waiting +=2;
	    else if (waiting < 200)*last_waiting ++;   //Maxmal waiting interval set to 200 second
		dio_output(NULL);
		ctimer_set(&periodic_dior_timer,waiting*CLOCK_SECOND,
				   handle_periodic_timer,last_waiting);		
}
#endif
/*---------------------------------------------------------------------------*/
void
rpl_reset_periodic_timer(void)        // Zuo 
{
  clock_time_t waiting;             // random waiting before send out first DIS
  waiting =  random_rand() % 30;   //waiting for 1-60 s randomly	
#ifdef LEAF
  waiting +=180;                      // leaves wait 180s until routers finished initializing
#endif
  ctimer_set(&periodic_dis_timer, waiting*CLOCK_SECOND, handle_periodic_timer, NULL);
}
/*---------------------------------------------------------------------------*/
#ifdef ROUTER
void
rpl_reset_dior_timer(void)
{
  uint16_t *waiting = 1;
  ctimer_set(&periodic_dior_timer, CLOCK_SECOND, handle_dior_timer, waiting);
#if RPL_CONF_STAT
  rpl_stats.resets++;
#endif /* RPL_CONF_STATS */
}
#endif
/*---------------------------------------------------------------------------*/
static void
handle_dao_timer(void *ptr)
{
  rpl_instance_t *instance;

  instance = (rpl_instance_t *)ptr;

  if(!dio_send_ok && uip_ds6_get_link_local(ADDR_PREFERRED) == NULL) {
    PRINTF("RPL: Postpone DAO transmission\n");
    ctimer_set(&instance->dao_timer, CLOCK_SECOND, handle_dao_timer, instance);
    return;
  }

  /* Send the DAO to the DAO parent set -- the preferred parent in our case. */
  if(instance->current_dag->preferred_parent != NULL) {
    PRINTF("RPL: handle_dao_timer - sending DAO\n");
    /* Set the route lifetime to the default value. */
    //dao_output(instance->current_dag->preferred_parent, instance->default_lifetime);
  } else {
    PRINTF("RPL: No suitable DAO parent\n");
  }
  ctimer_stop(&instance->dao_timer);
}
/*---------------------------------------------------------------------------*/
void
rpl_schedule_dao(rpl_instance_t *instance)
{
  clock_time_t expiration_time;

  expiration_time = etimer_expiration_time(&instance->dao_timer.etimer);

  if(!etimer_expired(&instance->dao_timer.etimer)) {
    PRINTF("RPL: DAO timer already scheduled\n");
  } else {
    expiration_time = RPL_DAO_LATENCY / 2 +
      (random_rand() % (RPL_DAO_LATENCY));
    PRINTF("RPL: Scheduling DAO timer %u ticks in the future\n",
           (unsigned)expiration_time);
    ctimer_set(&instance->dao_timer, expiration_time,
               handle_dao_timer, instance);
  }
}
/*---------------------------------------------------------------------------*/
#endif /* UIP_CONF_IPV6 */
