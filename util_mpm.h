
/**
 * \file
 *
 * \author 
 */

#ifndef __UTIL_MPM_H__
#define __UTIL_MPM_H__

#define MPM_ENDMATCH_SINGLE     0x01    /**< A single match is sufficient. No
                                             depth, offset, etc settings. */
#define MPM_ENDMATCH_OFFSET     0x02    /**< has offset setting */
#define MPM_ENDMATCH_DEPTH      0x04    /**< has depth setting */
#define MPM_ENDMATCH_NOSEARCH   0x08    /**< if this matches, no search is
                                             required (for this pattern) */

#define HASHSIZE_LOWEST         2048    /**< Lowest hash size for the multi
                                             pattern matcher algorithms */
#define HASHSIZE_LOW            4096    /**< Low hash size for the multi
                                             pattern matcher algorithms */
#define HASHSIZE_MEDIUM         8192    /**< Medium hash size for the multi
                                             pattern matcher algorithms */
#define HASHSIZE_HIGH           16384   /**< High hash size for the multi
                                             pattern matcher algorithms */
#define HASHSIZE_HIGHER         32768   /**< Higher hash size for the multi
                                             pattern matcher algorithms */
#define HASHSIZE_MAX            65536   /**< Max hash size for the multi
                                             pattern matcher algorithms */
#define BLOOMSIZE_LOW           512     /*<* Low bloomfilter size for the multi
                                            pattern matcher algorithms */
#define BLOOMSIZE_MEDIUM        1024    /**< Medium bloomfilter size for the multi
                                             pattern matcher algorithms */
#define BLOOMSIZE_HIGH          2048    /**< High bloomfilter size for the multi
                                             pattern matcher algorithms */

#define MPM_PACKET_BUFFER_LIMIT 2400
#define MPM_PACKET_SIZE_LIMIT   1500
#define MPM_PACKET_BUFFERS      10
#define MPM_BATCHING_TIMEOUT    1
#define MPM_PAGE_LOCKED         1
#define MPM_CUDA_STREAMS        2

enum {
    MPM_NOTSET = 0,

    /* wumanber as the name suggests */
    MPM_WUMANBER,
    /* bndmq 2 gram */
    MPM_B2G,
#ifdef __SC_CUDA_SUPPORT__
    MPM_B2G_CUDA,
#endif
    /* bndmq 3 gram */
    MPM_B3G,
    MPM_B2GC,
    MPM_B2GM,

    /* aho-corasick */
    MPM_AC,
    /* aho-corasick with compression */
    MPM_ACC,
    /* aho-corasick-goto-failure state based */
    MPM_AC_GFBS,
    MPM_AC_BS,
    /* table size */
    MPM_TABLE_SIZE,
};

typedef struct MpmMatchBucket_ {
    uint32_t len;
} MpmMatchBucket;

typedef struct MpmThreadCtx_ {
    void *ctx;

    uint32_t memory_cnt;
    uint32_t memory_size;
} MpmThreadCtx;

/** \brief helper structure for the pattern matcher engine. The Pattern Matcher
 *         thread has this and passes a pointer to it to the pattern matcher.
 *         The actual pattern matcher will fill the structure. */
typedef struct PatternMatcherQueue_ {
    uint32_t *pattern_id_array;     /** array with pattern id's that had a
                                        pattern match. These will be inspected
                                        futher by the detection engine. */
    uint32_t pattern_id_array_cnt;
    uint32_t pattern_id_array_size; /**< size in bytes */

    uint8_t *pattern_id_bitarray;   /** bitarray with pattern id matches */
    uint32_t pattern_id_bitarray_size; /**< size in bytes */
} PatternMatcherQueue;

typedef struct MpmCtx_ {
    void *ctx;
    uint16_t mpm_type;

    /* used uint16_t here to avoiding using a pad.  You can use a uint8_t
     * here as well */
    uint16_t global;

    uint32_t pattern_cnt;       /* unique patterns */

    uint16_t minlen;
    uint16_t maxlen;

    uint32_t memory_cnt;
    uint32_t memory_size;
} MpmCtx;

/* if we want to retrieve an unique mpm context from the mpm context factory
 * we should supply this as the key */
#define MPM_CTX_FACTORY_UNIQUE_CONTEXT -1

#define MPM_CTX_FACTORY_FLAGS_PREPARE_WITH_SIG_GROUP_BUILD 0x01

typedef struct MpmCtxFactoryItem_ {
    char *name;
    MpmCtx *mpm_ctx_ts;
    MpmCtx *mpm_ctx_tc;
    int32_t id;
    uint8_t flags;
} MpmCtxFactoryItem;

typedef struct MpmCtxFactoryContainer_ {
    MpmCtxFactoryItem *items;
    int32_t no_of_items;
} MpmCtxFactoryContainer;

typedef struct MpmCtxStruct_
{
	MpmCtx * mpm_ctx;
	MpmThreadCtx mpm_thread_ctx;
	PatternMatcherQueue pmq;
}MpmCtxStruct;

/** pattern is case insensitive */
#define MPM_PATTERN_FLAG_NOCASE     0x01
/** pattern is negated */
#define MPM_PATTERN_FLAG_NEGATED    0x02
/** pattern has a depth setting */
#define MPM_PATTERN_FLAG_DEPTH      0x04
/** pattern has an offset setting */
#define MPM_PATTERN_FLAG_OFFSET     0x08
/** one byte pattern (used in b2g) */
#define MPM_PATTERN_ONE_BYTE        0x10

typedef struct MpmTableElmt_ {
    const char *name;
    uint8_t max_pattern_length;
    void (*InitCtx)(struct MpmCtx_ *, int);
    void (*InitThreadCtx)(struct MpmCtx_ *, struct MpmThreadCtx_ *, uint32_t);
    void (*DestroyCtx)(struct MpmCtx_ *);
    void (*DestroyThreadCtx)(struct MpmCtx_ *, struct MpmThreadCtx_ *);

    /** function pointers for adding patterns to the mpm ctx.
     *
     *  \param mpm_ctx Mpm context to add the pattern to
     *  \param pattern pointer to the pattern
     *  \param pattern_len length of the pattern in bytes
     *  \param offset pattern offset setting
     *  \param depth pattern depth setting
     *  \param pid pattern id
     *  \param sid signature _internal_ id
     *  \param flags pattern flags
     */
    int  (*AddPattern)(struct MpmCtx_ *, uint8_t *, uint16_t, uint16_t, uint16_t, uint32_t, uint32_t, uint8_t);
    int  (*AddPatternNocase)(struct MpmCtx_ *, uint8_t *, uint16_t, uint16_t, uint16_t, uint32_t, uint32_t, uint8_t);
    int  (*Prepare)(struct MpmCtx_ *);
    uint32_t (*Search)(struct MpmCtx_ *, struct MpmThreadCtx_ *, PatternMatcherQueue *, uint8_t *, uint16_t);
    void (*Cleanup)(struct MpmThreadCtx_ *);
    void (*PrintCtx)(struct MpmCtx_ *);
    void (*PrintThreadCtx)(struct MpmThreadCtx_ *);
    void (*RegisterUnittests)(void);
    uint8_t flags;
} MpmTableElmt;

MpmTableElmt mpm_table[MPM_TABLE_SIZE];


int PmqSetup(PatternMatcherQueue *, uint32_t, uint32_t);
void PmqMerge(PatternMatcherQueue *src, PatternMatcherQueue *dst);
void PmqReset(PatternMatcherQueue *);
void PmqCleanup(PatternMatcherQueue *);
void PmqFree(PatternMatcherQueue *);


void MpmTableSetup(void);
void MpmRegisterTests(void);

/** Return the max pattern length of a Matcher type given as arg */
int32_t MpmMatcherGetMaxPatternLength(uint16_t);

int MpmVerifyMatch(MpmThreadCtx *, PatternMatcherQueue *, uint32_t);
void MpmInitCtx (MpmCtx *mpm_ctx, uint16_t matcher, int module_handle);
void MpmInitThreadCtx(MpmThreadCtx *mpm_thread_ctx, uint16_t, uint32_t);
uint32_t MpmGetHashSize(void);
uint32_t MpmGetBloomSize(void);

#endif /* __UTIL_MPM_H__ */

