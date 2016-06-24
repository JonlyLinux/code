


#define SC_AC_STATE_TYPE_U16 uint16_t
#define SC_AC_STATE_TYPE_U32 uint32_t

typedef struct SCACPattern_ {
    /* length of the pattern */
    uint16_t len;
    /* flags decribing the pattern */
    uint8_t flags;
    /* holds the original pattern that was added */
    uint8_t *original_pat;
    /* case sensitive */
    uint8_t *cs;
    /* case INsensitive */
    uint8_t *ci;
    /* pattern id */
    uint32_t id;

    struct SCACPattern_ *next;
} SCACPattern;

typedef struct SCACPatternList_ {
    uint8_t *cs;
    uint16_t patlen;
    uint16_t case_state;
} SCACPatternList;

typedef struct SCACOutputTable_ {
    /* list of pattern sids */
    uint32_t *pids;
    /* no of entries we have in pids */
    uint32_t no_of_entries;
} SCACOutputTable;


typedef struct SCACCtx_ {
    /* hash used during ctx initialization */
    SCACPattern **init_hash;

    /* pattern arrays.  We need this only during the goto table creation phase */
    SCACPattern **parray;

    /* no of states used by ac */
    uint32_t state_count;
    /* the all important memory hungry state_table */
    SC_AC_STATE_TYPE_U16 (*state_table_u16)[256];
    /* the all important memory hungry state_table */
    SC_AC_STATE_TYPE_U32 (*state_table_u32)[256];

    /* goto_table, failure table and output table.  Needed to create state_table.
     * Will be freed, once we have created the state_table */
    int32_t (*goto_table)[256];
    int32_t *failure_table;
    SCACOutputTable *output_table;
    SCACPatternList *pid_pat_list;

    /* the size of each state */
    uint16_t single_state_size;
    uint16_t max_pat_id;
} SCACCtx;


typedef struct SCACThreadCtx_ {
    /* the total calls we make to the search function */
    uint32_t total_calls;
    /* the total patterns that we ended up matching against */
    uint64_t total_matches;
} SCACThreadCtx;

void MpmACRegister(void);

