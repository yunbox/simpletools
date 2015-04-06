#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#include <inotifytools/inotifytools.h>
#include <inotifytools/inotify.h>

#define HAVE_LANGINFO_CODESET 1

#include <ctype.h>
#include <locale.h>
#if defined(HAVE_LOCALE_CHARSET)
# include <localcharset.h>
#elif defined (HAVE_LANGINFO_CODESET)
# include <langinfo.h>
# define locale_charset()  nl_langinfo(CODESET)
#endif
#include <iconv.h>

/* iconv encoding name for AlphaChar string */
#define ALPHA_ENC   "UCS-4LE"
#define N_ELEMENTS(a)   (sizeof(a)/sizeof((a)[0]))

#include <datrie/trie.h>

#define BLOCKING_TIMEOUT -1
#ifndef MAX_PATH
#define MAX_PATH    4096
#endif

typedef struct {
    const char *path;
    const char *trie_name;
    iconv_t    to_alpha_conv;
    iconv_t    from_alpha_conv;
    Trie       *trie;
} ProgEnv;

void warn_inotify_init_error()
{
    int error = inotifytools_error();
    fprintf(stderr, "Couldn't initialize inotify: %s\n", strerror(error));
    if (error == EMFILE) {
        fprintf(stderr, "Try increasing the value of /proc/sys/fs/inotify/max_user_instances\n");
    }
}

static void init_conv (ProgEnv *env)
{
    const char *prev_locale;
    const char *locale_codeset;

    prev_locale = setlocale (LC_CTYPE, "");
    locale_codeset = locale_charset();
    setlocale (LC_CTYPE, prev_locale);

    env->to_alpha_conv = iconv_open (ALPHA_ENC, locale_codeset);
    env->from_alpha_conv = iconv_open (locale_codeset, ALPHA_ENC);
}

static size_t conv_to_alpha (ProgEnv *env, const char *in, AlphaChar *out, size_t out_size)
{
    char   *in_p = (char *) in;
    char   *out_p = (char *) out;
    size_t  in_left = strlen (in);
    size_t  out_left = out_size * sizeof (AlphaChar);
    size_t  res;
    const unsigned char *byte_p;

    assert (sizeof (AlphaChar) == 4);

    /* convert to UCS-4LE */
    res = iconv (env->to_alpha_conv, (char **) &in_p, &in_left,
                 &out_p, &out_left);

    if (res < 0)
        return res;

    /* convert UCS-4LE to AlphaChar string */
    res = 0;
    for (byte_p = (const unsigned char *) out;
         res < out_size && byte_p + 3 < (unsigned char*) out_p;
         byte_p += 4)
    {
        out[res++] = byte_p[0]
                     | (byte_p[1] << 8)
                     | (byte_p[2] << 16)
                     | (byte_p[3] << 24);
    }
    if (res < out_size) {
        out[res] = 0;
    }

    return res;
}

static size_t conv_from_alpha (ProgEnv *env, const AlphaChar *in, char *out, size_t out_size)
{
    size_t  in_left = alpha_char_strlen (in) * sizeof (AlphaChar);
    size_t  res;

    assert (sizeof (AlphaChar) == 4);

    /* convert AlphaChar to UCS-4LE */
    for (res = 0; in[res]; res++) {
        unsigned char  b[4];

        b[0] = in[res] & 0xff;
        b[1] = (in[res] >> 8) & 0xff;
        b[2] = (in[res] >> 16) & 0xff;
        b[3] = (in[res] >> 24) & 0xff;

        memcpy ((char *) &in[res], b, 4);
    }

    /* convert UCS-4LE to locale codeset */
    res = iconv (env->from_alpha_conv, (char **) &in, &in_left,
                 &out, &out_size);
    *out = 0;

    return res;
}

static void close_conv (ProgEnv *env)
{
    iconv_close (env->to_alpha_conv);
    iconv_close (env->from_alpha_conv);
}

static void datrie_init (ProgEnv *env)
{
    AlphaMap   *alpha_map;
    char buff[MAX_PATH] = {0};
    
    init_conv(env);
    
    alpha_map = alpha_map_new ();
    alpha_map_add_range (alpha_map, 32, 126);

    snprintf (buff, sizeof (buff),
              "%s/%s.tri", env->path, env->trie_name);
    env->trie = trie_new_from_file (buff);

    if (!env->trie)
        env->trie = trie_new (alpha_map);
        
    alpha_map_free (alpha_map);
}

static int datrie_add (char *key, int data, ProgEnv *env)
{
    TrieData value = data;
    AlphaChar  key_alpha[MAX_PATH] = {0};

    conv_to_alpha (env, key, key_alpha, N_ELEMENTS (key_alpha));
    if (!trie_store (env->trie, key_alpha, value)) {
        fprintf (stderr, "Failed to add entry '%s' with value %d\n",
                 key, value);
    }

    return 0;
}

static int datrie_query (char *key, ProgEnv *env)
{
    AlphaChar  key_alpha[MAX_PATH] = {0};
    TrieData   data;
    
    conv_to_alpha (env, key, key_alpha, N_ELEMENTS (key_alpha));
    if (trie_retrieve (env->trie, key_alpha, &data)) {
        return data;
    } else {
        fprintf (stderr, "query: Key '%s' not found.\n", key);
        return 0;
    }
}

static int datrie_save (ProgEnv *env)
{
    if (trie_is_dirty (env->trie)) {
        char path[MAX_PATH] = {0};

        snprintf (path, sizeof (path),
                  "%s/%s.tri", env->path, env->trie_name);
        if (trie_save (env->trie, path) != 0) {
            fprintf (stderr, "Cannot save trie to %s\n", path);
            return -1;
        }
    }

    return 0;
}

static int datrie_close (ProgEnv *env)
{
    if (trie_is_dirty (env->trie)) {
        char path[MAX_PATH] = {0};

        snprintf (path, sizeof (path),
                  "%s/%s.tri", env->path, env->trie_name);
        if (trie_save (env->trie, path) != 0) {
            fprintf (stderr, "Cannot save trie to %s\n", path);
            return -1;
        }
    }

    trie_free (env->trie);
    close_conv(env);
    
    return 0;
}

static Bool list_enum_func (const AlphaChar *key, TrieData key_data, void *user_data)
{
    ProgEnv    *env = (ProgEnv *) user_data;
    char        key_locale[MAX_PATH] = {0};

    conv_from_alpha (env, key, key_locale, N_ELEMENTS (key_locale));
    printf ("%s\t%d\n", key_locale, key_data);
    return TRUE;
}

static int datrie_list (ProgEnv *env)
{
    trie_enumerate (env->trie, list_enum_func, (void *) env);
    return 0;
}

int main(int argc, char **argv)
{
    char *dirpath = NULL;
    char *watchpath, *dstr, *saveptr;
    int events = inotifytools_str_to_event("open");
    int rc = 0;
    long int timeout = BLOCKING_TIMEOUT;
    ProgEnv daenv = {"/tmp", "thinbox", NULL, NULL, NULL};
    
    if (argc != 2) {
        printf("Usage: %s watch-path\n", argv[0]);
        return 0;
    }
    
    dirpath = argv[1];
    
    if ( !inotifytools_initialize() ) {
        warn_inotify_init_error();
        return 1;
    }
	
    for (dstr = dirpath; ; dstr = NULL) {
        watchpath = strtok_r(dstr, ",", &saveptr);
        if (watchpath == NULL)
	    break;	        
        rc = inotifytools_watch_recursively(watchpath, events);
        if (!rc) {
            if ( inotifytools_error() == ENOSPC ) {
                printf("Failed to watch %s; upper limit on inotify "
		       "watches reached!\n", watchpath );
		printf("Please increase the amount of inotify watches "
		       "allowed per user via `/proc/sys/fs/inotify/"
		       "max_user_watches'.\n");
            } else {
                printf("Couldn't watch %s: %s\n", watchpath, strerror( inotifytools_error() ) );
            }
            return 1;
        }
    }
    
    // setup datrie
    datrie_init(&daenv);
	
    // list what we had
    printf("Files we have watched before:\n\n");
    printf("======= start of list ========\n\n");
    datrie_list(&daenv);
    printf("\n======= end of list ========\n\n");
	
    // Now wait till we get event
    struct inotify_event * event;
    char *evt_filename = NULL;
    char *evt_dirpath = NULL;
    char fullpath[MAX_PATH] = {0};
    TrieData   refcnt = 0;
    
    do {
        refcnt = 0;
        
        event = inotifytools_next_event( timeout );
        if ( !event ) {
            if ( !inotifytools_error() ) {
                return 1;
            } else {
                printf("%s\n", strerror( inotifytools_error() ) );
                return 1;
            }
        }
        
        // what we care
        memset(fullpath, 0, MAX_PATH);
        
        if (event->mask & events) {
            //datrie_list(&daenv);
            evt_dirpath = inotifytools_filename_from_wd( event->wd );
            if (event->len > 0) {
                evt_filename = event->name;
                snprintf(fullpath, MAX_PATH, "%s%s", evt_dirpath, evt_filename);                
                refcnt = datrie_query (fullpath, &daenv);
                if (refcnt == 0) {
                    printf ("file: %s opened the first time\n", fullpath);
                    datrie_add (fullpath, ++refcnt, &daenv);
                } else {
                    datrie_add (fullpath, ++refcnt, &daenv);
                    printf ("file: %s opened %d times\n", fullpath, refcnt);
                }
                datrie_save(&daenv);
            }
        } else {  // should never happen
            printf("event->mask = 0x%X, path: %s\n", event->mask, event->name);
        }
    } while(1);
    
    datrie_close(&daenv);
    
    return 0;
}
