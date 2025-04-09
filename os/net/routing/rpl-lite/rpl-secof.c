/**
 * \addtogroup rpl-lite
 * @{
 *
 * \file
 *         SECURE OBJECTIVE FUNCTON 
 *          
 *          The following objective function has been developed
 *          over the indications and information provided in the article:
 *          "Resolving the Decreased Rank Attack in RPL's IoT Networks"
 *          by B. Ghaleb, A. Al-Dubai, A. Hussain, J. Ahmad, I. I. Romdhani and Z. Jaroucheh.
 *
 * \author Silvia Brighi <s.brighi@student.tue.nl>
 */
#include "net/routing/rpl-lite/rpl.h"
#include "net/nbr-table.h"
#include "net/link-stats.h"

/* Log configuration */
#include "sys/log.h"
#define LOG_MODULE "RPL"
#define LOG_LEVEL LOG_LEVEL_RPL

/* Constants from RFC6552. We use the default values. */
#define RANK_STRETCH       0
#define RANK_FACTOR        1

#define MIN_STEP_OF_RANK   1
#define MAX_STEP_OF_RANK   9

#define MIN_HOPRANKINC     3 /* just example value */
#define ALPHA_THRESHOLD    2 /*  just example value */

/* Define Modes */
#define NORMAL_MODE        0
#define RESTRICTED_MODE    1

static int current_mode = NORMAL_MODE;  /* Toggle between Normal and Restricted modes */

static void
reset(void)
{
  LOG_INFO("reset secOf\n");
}

/* Functions for normal mode */
static uint16_t
nbr_link_metric(rpl_nbr_t *nbr) {
  const struct link_stats *stats = rpl_neighbor_get_link_stats(nbr);
  return stats != NULL ? stats->etx : 0xffff;
}

static int
nbr_has_usable_link(rpl_nbr_t *nbr)
{
  return 1;
}

/* Calculate rank increase based on neighbor */
static uint16_t
nbr_rank_increase(rpl_nbr_t *nbr) {
  uint16_t min_hoprankinc = curr_instance.min_hoprankinc;
  return (RANK_FACTOR * STEP_OF_RANK(nbr) + RANK_STRETCH) * min_hoprankinc;
}

/* Path cost calculation */
static uint16_t
nbr_path_cost(rpl_nbr_t *nbr) {
  if(nbr == NULL) {
    return 0xffff;
  }
  return MIN((uint32_t)nbr->rank + nbr_link_metric(nbr), 0xffff);
}

/* Rank calculation based on neighbor */
/* Equation 2 - 𝑅𝑎𝑛𝑘(𝑥)=𝑅𝑎𝑛𝑘 (𝑝) + 𝐸𝑇𝑋 (𝑥,𝑝(𝑥)) */
static rpl_rank_t
rank_via_nbr(rpl_nbr_t *nbr) {
  if(nbr == NULL) {
    return RPL_INFINITE_RANK;
  } else {
    return MIN((uint32_t)nbr->rank + nbr_rank_increase(nbr), RPL_INFINITE_RANK);
  }
}

/* Function to check if a parent can be accepted */
static int
nbr_is_acceptable_parent(rpl_nbr_t *nbr) {
  return STEP_OF_RANK(nbr) >= MIN_STEP_OF_RANK
      && STEP_OF_RANK(nbr) <= MAX_STEP_OF_RANK;
}

/* Function for mode switching */
static void
switch_mode() {
  if (current_mode == NORMAL_MODE) {
    current_mode = RESTRICTED_MODE;
    LOG_INFO("Switching to Restricted Mode\n");
  } else {
    current_mode = NORMAL_MODE;
    LOG_INFO("Switching to Normal Mode\n");
  }
}

/* Secure parent selection with mode check */
static rpl_nbr_t
*best_parent(rpl_nbr_t *nbr1, rpl_nbr_t *nbr2) {
  uint16_t nbr1_cost, nbr2_cost;
  int nbr1_is_acceptable, nbr2_is_acceptable;

  nbr1_is_acceptable = nbr1 != NULL && nbr_is_acceptable_parent(nbr1);
  nbr2_is_acceptable = nbr2 != NULL && nbr_is_acceptable_parent(nbr2);

  /* Restricted Mode: Enforce hop-count based restriction */
 
if (current_mode == RESTRICTED_MODE) {
    if (nbr1 != NULL && nbr2 != NULL) {
    /* Compare the rank difference between the two neighbors */

    /* Equation 5 - Rank(a') < Rank(a) - alpha AND h(a') <= h(a) */
    if (nbr1->rank > nbr2->rank - ALPHA_THRESHOLD) {

        if (nbr1->rank == nbr2->rank) {

          /* In case of equal ranks, prefer the one with a better link quality (lower ETX) */
          if (nbr_link_metric(nbr1) < nbr_link_metric(nbr2)) {

            return nbr1;  /* Select the one with better link quality */
        } else {
            return nbr2;  /* Select the one with better link quality */
        }
        }
    }
    }
}

  /* In Normal Mode, parent selection is free based on cost */
  if (!nbr1_is_acceptable) {
    return nbr2_is_acceptable ? nbr2 : NULL;
  }
  if (!nbr2_is_acceptable) {
    return nbr1_is_acceptable ? nbr1 : NULL;
  }

  nbr1_cost = nbr_path_cost(nbr1);
  nbr2_cost = nbr_path_cost(nbr2);

  /* Compare path costs */
  if (nbr1_cost != nbr2_cost) {
    return nbr1_cost < nbr2_cost ? nbr1 : nbr2;
  } else {
    /* In case of a tie, stick to the current preferred parent */
    if (nbr1 == curr_instance.dag.preferred_parent || nbr2 == curr_instance.dag.preferred_parent) {
      return curr_instance.dag.preferred_parent;
    }
    /* Choose the one with the better link metric */
    return nbr_link_metric(nbr1) < nbr_link_metric(nbr2) ? nbr1 : nbr2;
  }
}

/* Update the metric container for security updates */
static void
update_metric_container(void) {
  curr_instance.mc.type = RPL_DAG_MC_NONE;
}

/* Sec-OF Objective Function structure */
rpl_of_t rpl_secof = {
  reset,
  nbr_link_metric,
  nbr_has_usable_link,
  nbr_is_acceptable_parent,
  nbr_path_cost,
  rank_via_nbr,
  best_parent,
  update_metric_container,
  RPL_OCP_SECOF
};


