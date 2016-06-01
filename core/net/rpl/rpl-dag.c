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
 *         Logic for Directed Acyclic Graphs in RPL.
 *
 * \author Joakim Eriksson <joakime@sics.se>, Nicolas Tsiftes <nvt@sics.se>
 */


#include "contiki.h"
#include "net/rpl/rpl-private.h"
#include "net/uip.h"
#include "net/uip-nd6.h"
#include "net/nbr-table.h"
#include "net/uip-ds6-nbr.h"
#include "lib/list.h"
#include "lib/memb.h"
#include "sys/ctimer.h"

#include <limits.h>
#include <string.h>

#define DEBUG DEBUG_NONE 
#include "net/uip-debug.h"

#if UIP_CONF_IPV6
/*---------------------------------------------------------------------------*/
extern rpl_of_t RPL_OF;
static rpl_of_t * const objective_functions[] = {&RPL_OF};

/*---------------------------------------------------------------------------*/
/* RPL definitions. */

#ifndef RPL_CONF_GROUNDED
#define RPL_GROUNDED                    0
#else
#define RPL_GROUNDED                    RPL_CONF_GROUNDED
#endif /* !RPL_CONF_GROUNDED */

/*---------------------------------------------------------------------------*/
/* Per-parent RPL information */
NBR_TABLE(rpl_parent_t, rpl_parents);   //init a table whose data type is rpl_parent_t, and the name of the table is rpl_parents
/*---------------------------------------------------------------------------*/
/* Allocate instance table. */
rpl_instance_t instance_table[RPL_MAX_INSTANCES];
rpl_instance_t *default_instance;
/*---------------------------------------------------------------------------*/
void
rpl_dag_init(void)
{
  //nbr_table_register(rpl_parents, (nbr_table_callback *)rpl_remove_parent);   //set callback function for this table
}
/*---------------------------------------------------------------------------*/
uip_ipaddr_t *
rpl_get_parent_ipaddr(rpl_parent_t *p)
{
  rimeaddr_t *lladdr = nbr_table_get_lladdr(rpl_parents, p);
  return uip_ds6_nbr_ipaddr_from_lladdr(ds6_neighbors, (uip_lladdr_t *)lladdr);
}
/*---------------------------------------------------------------------------*/
static void
rpl_set_preferred_parent(rpl_dag_t *dag, rpl_parent_t *p)
{
  if(dag != NULL && dag->preferred_parent != p) {
    PRINTF("RPL: rpl_set_preferred_parent ");
    if(p != NULL) {
      PRINT6ADDR(rpl_get_parent_ipaddr(p));
    } else {
      PRINTF("NULL");
    }
    PRINTF(" used to be ");
    if(dag->preferred_parent != NULL) {
      PRINT6ADDR(rpl_get_parent_ipaddr(dag->preferred_parent));
    } else {
      PRINTF("NULL");
    }
    PRINTF("\n");

    /* Always keep the preferred parent locked, so it remains in the
     * neighbor table. */
    nbr_table_unlock(rpl_parents, dag->preferred_parent);
    nbr_table_lock(rpl_parents, p);
    dag->preferred_parent = p;
  }
}
/*---------------------------------------------------------------------------*/
static rpl_dag_t *
get_dag(uint8_t instance_id, uip_ipaddr_t *dag_id)
{
  rpl_instance_t *instance;
  rpl_dag_t *dag;
  int i;

  instance = rpl_get_instance(instance_id);
  if(instance == NULL) {
    return NULL;
  }

  for(i = 0; i < RPL_MAX_DAG_PER_INSTANCE; ++i) {
    dag = &instance->dag_table[i];
    if(dag->used && uip_ipaddr_cmp(&dag->dag_id, dag_id)) {
      return dag;
    }
  }

  return NULL;
}
int
rpl_repair_root(uint8_t instance_id)
{
  rpl_instance_t *instance;

  instance = rpl_get_instance(instance_id);
  if(instance == NULL ||
     instance->current_dag->rank != ROOT_RANK(instance)) {
    PRINTF("RPL: rpl_repair_root triggered but not root\n");
    return 0;
  }

  RPL_LOLLIPOP_INCREMENT(instance->current_dag->version);
  RPL_LOLLIPOP_INCREMENT(instance->dtsn_out);
  PRINTF("RPL: rpl_repair_root initiating global repair with version %d\n", instance->current_dag->version);
  //rpl_reset_dio_timer(instance);
  return 1;
}
/*---------------------------------------------------------------------------*/
static void
set_ip_from_prefix(uip_ipaddr_t *ipaddr, rpl_prefix_t *prefix)
{
  memset(ipaddr, 0, sizeof(uip_ipaddr_t));
  memcpy(ipaddr, &prefix->prefix, (prefix->length + 7) / 8);
  uip_ds6_set_addr_iid(ipaddr, &uip_lladdr);
}
/*---------------------------------------------------------------------------*/
static void
check_prefix(rpl_prefix_t *last_prefix, rpl_prefix_t *new_prefix)
{
  uip_ipaddr_t ipaddr;
  uip_ds6_addr_t *rep;

  if(last_prefix != NULL && new_prefix != NULL &&
     last_prefix->length == new_prefix->length &&
     uip_ipaddr_prefixcmp(&last_prefix->prefix, &new_prefix->prefix, new_prefix->length) &&
     last_prefix->flags == new_prefix->flags) {
    /* Nothing has changed. */
    return;
  }

  if(last_prefix != NULL) {
    set_ip_from_prefix(&ipaddr, last_prefix);
    rep = uip_ds6_addr_lookup(&ipaddr);
    if(rep != NULL) {
      PRINTF("RPL: removing global IP address ");
      PRINT6ADDR(&ipaddr);
      PRINTF("\n");
      uip_ds6_addr_rm(rep);
    }
  }
  
  if(new_prefix != NULL) {
    set_ip_from_prefix(&ipaddr, new_prefix);
    if(uip_ds6_addr_lookup(&ipaddr) == NULL) {
      PRINTF("RPL: adding global IP address ");
      PRINT6ADDR(&ipaddr);
      PRINTF("\n");
      uip_ds6_addr_add(&ipaddr, 0, ADDR_AUTOCONF);
    }
  }
}
/*---------------------------------------------------------------------------*/
int
rpl_set_prefix(rpl_dag_t *dag, uip_ipaddr_t *prefix, unsigned len)
{
  rpl_prefix_t last_prefix;
  uint8_t last_len = dag->prefix_info.length;
  
  if(len > 128) {
    return 0;
  }
  if(dag->prefix_info.length != 0) {
    memcpy(&last_prefix, &dag->prefix_info, sizeof(rpl_prefix_t)); //store old prefix
  }
  PRINTF("old prefix is ");  /*Zuo*/
  PRINT6ADDR(&last_prefix.prefix); //Zuo
  PRINTF("\n");  //Zuo
  memset(&dag->prefix_info.prefix, 0, sizeof(dag->prefix_info.prefix));
  memcpy(&dag->prefix_info.prefix, prefix, (len + 7) / 8);         //update new prefix  (len + 7) / 8
  PRINTF("new prefix is ");  /*Zuo*/
  PRINT6ADDR(&dag->prefix_info.prefix); //Zuo
  PRINTF("\n");  //Zuo
  dag->prefix_info.length = len;
  dag->prefix_info.flags = UIP_ND6_RA_FLAG_AUTONOMOUS;
  PRINTF("RPL: Prefix set - will announce this in DIOs\n");
  /* Autoconfigure an address if this node does not already have an address
     with this prefix. Otherwise, update the prefix */
  if(last_len == 0) {
    PRINTF("rpl_set_prefix - prefix NULL\n");
    check_prefix(NULL, &dag->prefix_info);
  } else { 
    PRINTF("rpl_set_prefix - prefix NON-NULL\n");
    check_prefix(&last_prefix, &dag->prefix_info);
  }
  
  return 1;
}
/*---------------------------------------------------------------------------*/
int
rpl_set_default_route(rpl_instance_t *instance, uip_ipaddr_t *from)
{
  if(instance->def_route != NULL) {
    PRINTF("RPL: Removing default route through ");
    PRINT6ADDR(&instance->def_route->ipaddr);
    PRINTF("\n");
    uip_ds6_defrt_rm(instance->def_route);
    instance->def_route = NULL;
  }

  if(from != NULL) {
    PRINTF("RPL: Adding default route through ");
    PRINT6ADDR(from);
    PRINTF("\n");
    instance->def_route = uip_ds6_defrt_add(from,
        RPL_LIFETIME(instance,
            instance->default_lifetime));
    if(instance->def_route == NULL) {
      return 0;
    }
  } else {
    PRINTF("RPL: Removing default route\n");
    if(instance->def_route != NULL) {
      uip_ds6_defrt_rm(instance->def_route);
    } else {
      PRINTF("RPL: Not actually removing default route, since instance had no default route\n");
    }
  }
  return 1;
}
/*---------------------------------------------------------------------------*/
rpl_dag_t *
rpl_alloc_dag(uint8_t instance_id, uip_ipaddr_t *dag_id)
{
  rpl_dag_t *dag, *end;
  rpl_instance_t *instance;

  instance = rpl_get_instance(instance_id);
  

  for(dag = &instance->dag_table[0], end = dag + RPL_MAX_DAG_PER_INSTANCE; dag < end; ++dag) {
    if(!dag->used) {
      memset(dag, 0, sizeof(*dag));
      dag->used = 1;
      dag->rank = INFINITE_RANK;
      dag->min_rank = INFINITE_RANK;
      dag->instance = instance;
      return dag;
    }
  }

  RPL_STAT(rpl_stats.mem_overflows++);
  //rpl_free_instance(instance);
  return NULL;
}
/*---------------------------------------------------------------------------*/
void
rpl_set_default_instance(rpl_instance_t *instance)
{
  default_instance = instance;
}
/*---------------------------------------------------------------------------*/
rpl_parent_t *
rpl_add_parent(rpl_dag_t *dag, rpl_dio_t *dio, uip_ipaddr_t *addr)
{
  rpl_parent_t *p = NULL;
  /* Is the parent known by ds6? Drop this request if not.
   * Typically, the parent is added upon receiving a DIO. */
  uip_lladdr_t *lladdr = uip_ds6_nbr_lladdr_from_ipaddr(ds6_neighbors, addr);

  PRINTF("RPL: rpl_add_parent lladdr %p\n", lladdr);
  if(lladdr != NULL) {
    /* Add parent in rpl_parents */
    p = nbr_table_add_lladdr(rpl_parents, (rimeaddr_t *)lladdr);
    p->dag = dag;
    p->rank = dio->rank;
    p->dtsn = dio->dtsn;
    p->link_metric = RPL_INIT_LINK_METRIC * RPL_DAG_MC_ETX_DIVISOR;
#if RPL_DAG_MC != RPL_DAG_MC_NONE
    memcpy(&p->mc, &dio->mc, sizeof(p->mc));
#endif /* RPL_DAG_MC != RPL_DAG_MC_NONE */
  }
  return p;
}
/*---------------------------------------------------------------------------*/
static rpl_parent_t *
find_parent_any_dag_any_instance(uip_ipaddr_t *addr)
{
  uip_ds6_nbr_t *ds6_nbr = uip_ds6_nbr_lookup(ds6_neighbors,addr);
  uip_lladdr_t *lladdr = uip_ds6_nbr_get_ll(ds6_neighbors, ds6_nbr);
  return nbr_table_get_from_lladdr(rpl_parents, (rimeaddr_t *)lladdr);
}
/*---------------------------------------------------------------------------*/
rpl_parent_t *
rpl_find_parent(rpl_dag_t *dag, uip_ipaddr_t *addr)
{
  rpl_parent_t *p = find_parent_any_dag_any_instance(addr);
  if(p != NULL && p->dag == dag) {
    return p;
  } else {
    return NULL;
  }
}
/*---------------------------------------------------------------------------*/
static rpl_dag_t *
find_parent_dag(rpl_instance_t *instance, uip_ipaddr_t *addr)
{
  rpl_parent_t *p = find_parent_any_dag_any_instance(addr);
  if(p != NULL) {
    return p->dag;
  } else {
    return NULL;
  }
}
/*---------------------------------------------------------------------------*/
rpl_parent_t *
rpl_find_parent_any_dag(rpl_instance_t *instance, uip_ipaddr_t *addr)
{
  rpl_parent_t *p = find_parent_any_dag_any_instance(addr);
  if(p && p->dag && p->dag->instance == instance) {
    return p;
  } else {
    return NULL;
  }
}
/*---------------------------------------------------------------------------*/
rpl_instance_t *
rpl_get_instance(uint8_t instance_id)
{
  int i;

  for(i = 0; i < RPL_MAX_INSTANCES; ++i) {
    if(instance_table[i].used && instance_table[i].instance_id == instance_id) {
      return &instance_table[i];
    }
  }
  return NULL;
}
/*---------------------------------------------------------------------------*/
#endif /* UIP_CONF_IPV6 */
