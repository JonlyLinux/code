
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <malloc.h>

#include "util_mpm.h"
#include "util_mpm_ac.h"

#define SCThreadMalloc malloc
#define SCFree free
#define SCEnter()
#define SCReturnInt return

/**
 *  \brief Setup a pmq
 *
 *  \param pmq Pattern matcher queue to be initialized
 *  \param maxid Max sig id to be matched on
 *  \param patmaxid Max pattern id to be matched on
 *
 *  \retval -1 error
 *  \retval 0 ok
 */
int PmqSetup(PatternMatcherQueue *pmq, __attribute__((unused))uint32_t sig_maxid, uint32_t patmaxid) {
    SCEnter();
    //SCLogDebug("sig_maxid %u, patmaxid %u", sig_maxid, patmaxid);

    if (pmq == NULL) {
        SCReturnInt(-1);
    }

    memset(pmq, 0, sizeof(PatternMatcherQueue));

    if (patmaxid > 0) {
        pmq->pattern_id_array_size = patmaxid * sizeof(uint32_t);

        pmq->pattern_id_array = SCThreadMalloc(pmq->pattern_id_array_size);
        if (pmq->pattern_id_array == NULL) {
            SCReturnInt(-1);
        }
        memset(pmq->pattern_id_array, 0, pmq->pattern_id_array_size);
        pmq->pattern_id_array_cnt = 0;

        /* lookup bitarray */
        pmq->pattern_id_bitarray_size = (patmaxid / 8) + 1;

        pmq->pattern_id_bitarray = SCThreadMalloc(pmq->pattern_id_bitarray_size);
        if (pmq->pattern_id_bitarray == NULL) {
            SCReturnInt(-1);
        }
        memset(pmq->pattern_id_bitarray, 0, pmq->pattern_id_bitarray_size);

        //SCLogDebug("pmq->pattern_id_array %p, pmq->pattern_id_bitarray %p",
                //pmq->pattern_id_array, pmq->pattern_id_bitarray);
    }

    SCReturnInt(0);
}

/** \brief Verify and store a match
 *
 *   used at search runtime
 *
 *  \param thread_ctx mpm thread ctx
 *  \param pmq storage for match results
 *  \param list end match to check against (entire list will be checked)
 *  \param offset match offset in the buffer
 *  \param patlen length of the pattern we're checking
 *
 *  \retval 0 no match after all
 *  \retval 1 (new) match
 */
int
MpmVerifyMatch(__attribute__((unused))MpmThreadCtx *thread_ctx, PatternMatcherQueue *pmq, uint32_t patid)
{
    SCEnter();

    /* Handle pattern id storage */
    if (pmq != NULL && pmq->pattern_id_bitarray != NULL) {
        //SCLogDebug("using pattern id arrays, storing %"PRIu32, patid);

        if (!(pmq->pattern_id_bitarray[(patid / 8)] & (1<<(patid % 8)))) {
            /* flag this pattern id as being added now */
            pmq->pattern_id_bitarray[(patid / 8)] |= (1<<(patid % 8));
            /* append the pattern_id to the array with matches */
            pmq->pattern_id_array[pmq->pattern_id_array_cnt] = patid;
            pmq->pattern_id_array_cnt++;
            //SCLogDebug("pattern_id_array_cnt %u", pmq->pattern_id_array_cnt);
        }
    }

    SCReturnInt(1);
}

/**
 *  \brief Merge two pmq's bitarrays
 *
 *  \param src source pmq
 *  \param dst destination pmq to merge into
 */
void PmqMerge(PatternMatcherQueue *src, PatternMatcherQueue *dst) {
    uint32_t u;

    if (src->pattern_id_array_cnt == 0)
        return;

    for (u = 0; u < src->pattern_id_bitarray_size && u < dst->pattern_id_bitarray_size; u++) {
        dst->pattern_id_bitarray[u] |= src->pattern_id_bitarray[u];
    }

    /** \todo now set merged flag? */
}

/** \brief Reset a Pmq for reusage. Meant to be called after a single search.
 *  \param pmq Pattern matcher to be reset.
 *  \todo memset is expensive, but we need it as we merge pmq's. We might use
 *        a flag so we can clear pmq's the old way if we can.
 */
void PmqReset(PatternMatcherQueue *pmq) {
    if (pmq == NULL)
        return;

    memset(pmq->pattern_id_bitarray, 0, pmq->pattern_id_bitarray_size);
    //memset(pmq->pattern_id_array, 0, pmq->pattern_id_array_size);
    pmq->pattern_id_array_cnt = 0;
/*
    uint32_t u;
    for (u = 0; u < pmq->pattern_id_array_cnt; u++) {
        pmq->pattern_id_bitarray[(pmq->pattern_id_array[u] / 8)] &= ~(1<<(pmq->pattern_id_array[u] % 8));
    }
    pmq->pattern_id_array_cnt = 0;
*/
}

/** \brief Cleanup a Pmq
  * \param pmq Pattern matcher queue to be cleaned up.
  */
void PmqCleanup(PatternMatcherQueue *pmq) {
    if (pmq == NULL)
        return;

    if (pmq->pattern_id_array != NULL) {
        SCFree(pmq->pattern_id_array);
        pmq->pattern_id_array = NULL;
    }

    if (pmq->pattern_id_bitarray != NULL) {
        SCFree(pmq->pattern_id_bitarray);
        pmq->pattern_id_bitarray = NULL;
    }

    pmq->pattern_id_array_cnt = 0;
}

/** \brief Cleanup and free a Pmq
  * \param pmq Pattern matcher queue to be free'd.
  */
void PmqFree(PatternMatcherQueue *pmq) {
    if (pmq == NULL)
        return;

    PmqCleanup(pmq);
}

/**
 * \brief Return the pattern max length of a registered matcher
 * \retval 0 if it has no limit
 * \retval max_pattern_length of the specified matcher type
 * \retval -1 if the type is not registered return -1
 */
int32_t MpmMatcherGetMaxPatternLength(uint16_t matcher) {
    if (matcher < MPM_TABLE_SIZE)
        return mpm_table[matcher].max_pattern_length;
    else
        return -1;
}

void MpmInitThreadCtx(MpmThreadCtx *mpm_thread_ctx, uint16_t matcher, uint32_t max_id) {
    mpm_table[matcher].InitThreadCtx(NULL, mpm_thread_ctx, max_id);
}

void MpmInitCtx (MpmCtx *mpm_ctx, uint16_t matcher, int module_handle) {
    mpm_ctx->mpm_type = matcher;
    mpm_table[matcher].InitCtx(mpm_ctx, module_handle);
}

void MpmTableSetup(void) {
    memset(mpm_table, 0, sizeof(mpm_table));

    //MpmWuManberRegister();
    //MpmB2gRegister();
/*#ifdef __SC_CUDA_SUPPORT__
    MpmB2gCudaRegister();
#endif
    MpmB3gRegister();
    MpmB2gcRegister();
    MpmB2gmRegister();*/
    MpmACRegister();
/*    MpmACCRegister();
    MpmACBSRegister();
    MpmACGfbsRegister();*/
}

/** \brief  Function to return the default hash size for the mpm algorithm,
 *          which has been defined by the user in the config file
 *
 *  \param  conf_val    pointer to the string value of hash size
 *  \retval hash_value  returns the hash value as defined by user, otherwise
 *                      default low size value
 */
uint32_t MpmGetHashSize(void)
{
    return HASHSIZE_LOW;
}

/** \brief  Function to return the default bloomfilter size for the mpm algorithm,
 *          which has been defined by the user in the config file
 *
 *  \param  conf_val    pointer to the string value of bloom filter size
 *  \retval bloom_value returns the bloom filter value as defined by user,
 *                      otherwise default medium size value
 */
uint32_t MpmGetBloomSize(void)
{
    return BLOOMSIZE_MEDIUM;
}

