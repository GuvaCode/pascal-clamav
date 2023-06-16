unit clamav;

{$MINENUMSIZE 4}

interface

const
  {$IF Defined(WINDOWS)}
  cDllName = 'clamav.dll';
  {$ELSEIF Defined(LINUX)}
  cDllName = 'libclamav.so';
  {$ELSE}
    {$MESSAGE Error 'Unsupported platform'}
  {$ENDIF}

const
  _SF64_PREFIX = 'll';
  PRIu64 = _SF64_PREFIX + 'u';
  PRIx64 = _SF64_PREFIX + 'i';
  PRIi64 = _SF64_PREFIX + 'x';
  STDu64 = '%' + PRIu64;
  STDi64 = '%' + PRIi64;
  STDx64 = '%' + PRIx64;
  _SF32_PREFIX = 'l';
  PRIu32 = _SF32_PREFIX + 'u';
  PRIi32 = _SF32_PREFIX + 'i';
  PRIx32 = _SF32_PREFIX + 'x';
  STDu32 = '%' + PRIu32;
  STDi32 = '%' + PRIi32;
  STDx32 = '%' + PRIx32;
  INT32_MAX = 2147483647;
  CLAMAV_VERSION = '0.103.5';
  CLAMAV_VERSION_NUM = $006600;
  LIBCLAMAV_VERSION = '9:4:0';
  LIBCLAMAV_VERSION_NUM = $090400;
  LIBFRESHCLAM_VERSION = '2:0:0';
  LIBFRESHCLAM_VERSION_NUM = $020000;
  STAT64_BLACKLIST = 1;
  CL_COUNT_PRECISION = 4096;
  CL_DB_PHISHING = $2;
  CL_DB_PHISHING_URLS = $8;
  CL_DB_PUA = $10;
  CL_DB_CVDNOTMP = $20;
  CL_DB_OFFICIAL = $40;
  CL_DB_PUA_MODE = $80;
  CL_DB_PUA_INCLUDE = $100;
  CL_DB_PUA_EXCLUDE = $200;
  CL_DB_COMPILED = $400;
  CL_DB_DIRECTORY = $800;
  CL_DB_OFFICIAL_ONLY = $1000;
  CL_DB_BYTECODE = $2000;
  CL_DB_SIGNED = $4000;
  CL_DB_BYTECODE_UNSIGNED = $8000;
  CL_DB_UNSIGNED = $10000;
  CL_DB_BYTECODE_STATS = $20000;
  CL_DB_ENHANCED = $40000;
  CL_DB_PCRE_STATS = $80000;
  CL_DB_YARA_EXCLUDE = $100000;
  CL_DB_YARA_ONLY = $200000;
  CL_DB_STDOPT = (CL_DB_PHISHING or CL_DB_PHISHING_URLS or CL_DB_BYTECODE);
  CL_SCAN_GENERAL_ALLMATCHES = $1;
  CL_SCAN_GENERAL_COLLECT_METADATA = $2;
  CL_SCAN_GENERAL_HEURISTICS = $4;
  CL_SCAN_GENERAL_HEURISTIC_PRECEDENCE = $8;
  CL_SCAN_GENERAL_UNPRIVILEGED = $10;
  CL_SCAN_PARSE_ARCHIVE = $1;
  CL_SCAN_PARSE_ELF = $2;
  CL_SCAN_PARSE_PDF = $4;
  CL_SCAN_PARSE_SWF = $8;
  CL_SCAN_PARSE_HWP3 = $10;
  CL_SCAN_PARSE_XMLDOCS = $20;
  CL_SCAN_PARSE_MAIL = $40;
  CL_SCAN_PARSE_OLE2 = $80;
  CL_SCAN_PARSE_HTML = $100;
  CL_SCAN_PARSE_PE = $200;
  CL_SCAN_HEURISTIC_BROKEN = $2;
  CL_SCAN_HEURISTIC_EXCEEDS_MAX = $4;
  CL_SCAN_HEURISTIC_PHISHING_SSL_MISMATCH = $8;
  CL_SCAN_HEURISTIC_PHISHING_CLOAK = $10;
  CL_SCAN_HEURISTIC_MACROS = $20;
  CL_SCAN_HEURISTIC_ENCRYPTED_ARCHIVE = $40;
  CL_SCAN_HEURISTIC_ENCRYPTED_DOC = $80;
  CL_SCAN_HEURISTIC_PARTITION_INTXN = $100;
  CL_SCAN_HEURISTIC_STRUCTURED = $200;
  CL_SCAN_HEURISTIC_STRUCTURED_SSN_NORMAL = $400;
  CL_SCAN_HEURISTIC_STRUCTURED_SSN_STRIPPED = $800;
  CL_SCAN_HEURISTIC_STRUCTURED_CC = $1000;
  CL_SCAN_HEURISTIC_BROKEN_MEDIA = $2000;
  CL_SCAN_MAIL_PARTIAL_MESSAGE = $1;
  CL_SCAN_DEV_COLLECT_SHA = $1;
  CL_SCAN_DEV_COLLECT_PERFORMANCE_INFO = $2;
  CL_COUNTSIGS_OFFICIAL = $1;
  CL_COUNTSIGS_UNOFFICIAL = $2;
  CL_COUNTSIGS_ALL = (CL_COUNTSIGS_OFFICIAL or CL_COUNTSIGS_UNOFFICIAL);
  ENGINE_OPTIONS_NONE = $0;
  ENGINE_OPTIONS_DISABLE_CACHE = $1;
  ENGINE_OPTIONS_FORCE_TO_DISK = $2;
  ENGINE_OPTIONS_DISABLE_PE_STATS = $4;
  ENGINE_OPTIONS_DISABLE_PE_CERTS = $8;
  ENGINE_OPTIONS_PE_DUMPCERTS = $10;
  CL_INIT_DEFAULT = $0;
  MD5_HASH_SIZE = 16;
  SHA1_HASH_SIZE = 20;
  SHA256_HASH_SIZE = 32;
  SHA384_HASH_SIZE = 48;
  SHA512_HASH_SIZE = 64;

type
  // Forward declarations
  PPChar = ^PChar;
  Pcl_engine = Pointer;
  PPcl_engine = ^Pcl_engine;
  Pcl_settings = Pointer;
  PPcl_settings = ^Pcl_settings;
  Pstat = Pointer;
  PPstat = ^Pstat;
  Pcl_fmap = Pointer;
  PPcl_fmap = ^Pcl_fmap;
  Ptm = Pointer;
  PPtm = ^Ptm;
  Pcl_scan_options = ^cl_scan_options;
  Pcli_section_hash = ^cli_section_hash;
  Pcli_stats_sections = ^cli_stats_sections;
  Pcl_cvd = ^cl_cvd;
  Pcl_stat = ^cl_stat;

  (* return codes *)
  cl_error_t = (
    (* libclamav specific *)
    CL_CLEAN = 0,
    (* libclamav specific *)
    CL_SUCCESS = 0,
    (* libclamav specific *)
    CL_VIRUS = 1,
    (* libclamav specific *)
    CL_ENULLARG = 2,
    (* libclamav specific *)
    CL_EARG = 3,
    (* libclamav specific *)
    CL_EMALFDB = 4,
    (* libclamav specific *)
    CL_ECVD = 5,
    (* libclamav specific *)
    CL_EVERIFY = 6,
    (* libclamav specific *)
    CL_EUNPACK = 7,
    (* I/O and memory errors *)
    CL_EOPEN = 8,
    (* I/O and memory errors *)
    CL_ECREAT = 9,
    (* I/O and memory errors *)
    CL_EUNLINK = 10,
    (* I/O and memory errors *)
    CL_ESTAT = 11,
    (* I/O and memory errors *)
    CL_EREAD = 12,
    (* I/O and memory errors *)
    CL_ESEEK = 13,
    (* I/O and memory errors *)
    CL_EWRITE = 14,
    (* I/O and memory errors *)
    CL_EDUP = 15,
    (* I/O and memory errors *)
    CL_EACCES = 16,
    (* I/O and memory errors *)
    CL_ETMPFILE = 17,
    (* I/O and memory errors *)
    CL_ETMPDIR = 18,
    (* I/O and memory errors *)
    CL_EMAP = 19,
    (* I/O and memory errors *)
    CL_EMEM = 20,
    (* I/O and memory errors *)
    CL_ETIMEOUT = 21,
    (* internal (not reported outside libclamav) *)
    CL_BREAK = 22,
    (* internal (not reported outside libclamav) *)
    CL_EMAXREC = 23,
    (* internal (not reported outside libclamav) *)
    CL_EMAXSIZE = 24,
    (* internal (not reported outside libclamav) *)
    CL_EMAXFILES = 25,
    (* internal (not reported outside libclamav) *)
    CL_EFORMAT = 26,
    (* internal (not reported outside libclamav) *)
    CL_EPARSE = 27,
    (* may be reported in testmode *)
    CL_EBYTECODE = 28,
    (* may be reported in testmode *)
    CL_EBYTECODE_TESTFAIL = 29,
    (* c4w error codes *)
    CL_ELOCK = 30,
    (* c4w error codes *)
    CL_EBUSY = 31,
    (* c4w error codes *)
    CL_ESTATE = 32,
    (* The binary has been deemed trusted *)
    CL_VERIFIED = 33,
    (* Unspecified / generic error *)
    CL_ERROR = 34,
    (* no error codes below this line please *)
    CL_ELAST_ERROR = 35);
  Pcl_error_t = ^cl_error_t;

  cl_scan_options = record
    general: Cardinal;
    parse: Cardinal;
    heuristic: Cardinal;
    mail: Cardinal;
    dev: Cardinal;
  end;

  cl_engine_field = (
    (* uint64_t *)
    CL_ENGINE_MAX_SCANSIZE = 0,
    (* uint64_t *)
    CL_ENGINE_MAX_FILESIZE = 1,
    (* uint32_t *)
    CL_ENGINE_MAX_RECURSION = 2,
    (* uint32_t *)
    CL_ENGINE_MAX_FILES = 3,
    (* uint32_t *)
    CL_ENGINE_MIN_CC_COUNT = 4,
    (* uint32_t *)
    CL_ENGINE_MIN_SSN_COUNT = 5,
    (* (char * ) *)
    CL_ENGINE_PUA_CATEGORIES = 6,
    (* uint32_t *)
    CL_ENGINE_DB_OPTIONS = 7,
    (* uint32_t *)
    CL_ENGINE_DB_VERSION = 8,
    (* time_t *)
    CL_ENGINE_DB_TIME = 9,
    (* uint32_t *)
    CL_ENGINE_AC_ONLY = 10,
    (* uint32_t *)
    CL_ENGINE_AC_MINDEPTH = 11,
    (* uint32_t *)
    CL_ENGINE_AC_MAXDEPTH = 12,
    (* (char * ) *)
    CL_ENGINE_TMPDIR = 13,
    (* uint32_t *)
    CL_ENGINE_KEEPTMP = 14,
    (* uint32_t *)
    CL_ENGINE_BYTECODE_SECURITY = 15,
    (* uint32_t *)
    CL_ENGINE_BYTECODE_TIMEOUT = 16,
    (* uint32_t *)
    CL_ENGINE_BYTECODE_MODE = 17,
    (* uint64_t *)
    CL_ENGINE_MAX_EMBEDDEDPE = 18,
    (* uint64_t *)
    CL_ENGINE_MAX_HTMLNORMALIZE = 19,
    (* uint64_t *)
    CL_ENGINE_MAX_HTMLNOTAGS = 20,
    (* uint64_t *)
    CL_ENGINE_MAX_SCRIPTNORMALIZE = 21,
    (* uint64_t *)
    CL_ENGINE_MAX_ZIPTYPERCG = 22,
    (* uint32_t *)
    CL_ENGINE_FORCETODISK = 23,
    (* uint32_t *)
    CL_ENGINE_DISABLE_CACHE = 24,
    (* uint32_t *)
    CL_ENGINE_DISABLE_PE_STATS = 25,
    (* uint32_t *)
    CL_ENGINE_STATS_TIMEOUT = 26,
    (* uint32_t *)
    CL_ENGINE_MAX_PARTITIONS = 27,
    (* uint32_t *)
    CL_ENGINE_MAX_ICONSPE = 28,
    (* uint32_t *)
    CL_ENGINE_MAX_RECHWP3 = 29,
    (* uint32_t *)
    CL_ENGINE_MAX_SCANTIME = 30,
    (* uint64_t *)
    CL_ENGINE_PCRE_MATCH_LIMIT = 31,
    (* uint64_t *)
    CL_ENGINE_PCRE_RECMATCH_LIMIT = 32,
    (* uint64_t *)
    CL_ENGINE_PCRE_MAX_FILESIZE = 33,
    (* uint32_t *)
    CL_ENGINE_DISABLE_PE_CERTS = 34,
    (* uint32_t *)
    CL_ENGINE_PE_DUMPCERTS = 35);
  Pcl_engine_field = ^cl_engine_field;

  bytecode_security = (
    (* obsolete *)
    CL_BYTECODE_TRUST_ALL = 0,
    (* default *)
    CL_BYTECODE_TRUST_SIGNED = 1,
    (* paranoid setting *)
    CL_BYTECODE_TRUST_NOTHING = 2);
  Pbytecode_security = ^bytecode_security;

  bytecode_mode = (
    (* JIT if possible, fallback to interpreter *)
    CL_BYTECODE_MODE_AUTO = 0,
    (* force JIT *)
    CL_BYTECODE_MODE_JIT = 1,
    (* force interpreter *)
    CL_BYTECODE_MODE_INTERPRETER = 2,
    (* both JIT and interpreter, compare results, all failures are fatal *)
    CL_BYTECODE_MODE_TEST = 3,
    (* for query only, not settable *)
    CL_BYTECODE_MODE_OFF = 4);
  Pbytecode_mode = ^bytecode_mode;

  cli_section_hash = record
    md5: array [0..15] of Byte;
    len: NativeUInt;
  end;

  cli_stats_sections = record
    nsections: NativeUInt;
    sections: Pcli_section_hash;
  end;

  stats_section_t = cli_stats_sections;
  Pstats_section_t = ^stats_section_t;

  (* Pre-cache callback.
     Called for each processed file (both the entry level - AKA 'outer' - file and
     inner files - those generated when processing archive and container files), before
     the actual scanning takes place.
     @param(fd File descriptor which is about to be scanned.)
     @param(type File type detected via magic - i.e. NOT on the fly - (e.g. "CL_TYPE_MSEXE").)
     @param(context Opaque application provided data.)
     @returns(CL_CLEAN = File is scanned.)
     @returns(CL_BREAK = Whitelisted by callback - file is skipped and marked as clean.)
     @returns(CL_VIRUS = Blacklisted by callback - file is skipped and marked as infected.) *)
  clcb_pre_cache = function(fd: Integer; const _type: PChar; context: Pointer): cl_error_t; cdecl;

  (* Pre-scan callback.
     Called for each NEW file (inner and outer) before the scanning takes place. This is
     roughly the the same as clcb_before_cache, but it is affected by clean file caching.
     This means that it won't be called if a clean cached file (inner or outer) is
     scanned a second time.
     @param(fd File descriptor which is about to be scanned.)
     @param(type File type detected via magic - i.e. NOT on the fly - (e.g. "CL_TYPE_MSEXE").)
     @param(context Opaque application provided data.)
     @returns(CL_CLEAN = File is scanned.)
     @returns(CL_BREAK = Whitelisted by callback - file is skipped and marked as clean.)
     @returns(CL_VIRUS = Blacklisted by callback - file is skipped and marked as infected.) *)
  clcb_pre_scan = function(fd: Integer; const _type: PChar; context: Pointer): cl_error_t; cdecl;

  (* Post-scan callback.
     Called for each processed file (inner and outer), after the scanning is complete.
     In all-match mode, the virname will be one of the matches, but there is no
     guarantee in which order the matches will occur, thus the final virname may
     be any one of the matches.
     @param(fd File descriptor which was scanned.)
     @param(result The scan result for the file.)
     @param(virname A signature name if there was one or more matches.)
     @param(context Opaque application provided data.)
     @returns(Scan result is not overridden.)
     @returns(CL_BREAK = Whitelisted by callback - scan result is set to CL_CLEAN.)
     @returns(Blacklisted by callback - scan result is set to CL_VIRUS.) *)
  clcb_post_scan = function(fd: Integer; result: Integer; const virname: PChar; context: Pointer): cl_error_t; cdecl;

  (* Post-scan callback.
     Called for each signature match.
     If all-match is enabled, clcb_virus_found() may be called multiple times per
     scan.
     
     In addition, clcb_virus_found() does not have a return value and thus.
     can not be used to whitelist the match.
     @param(fd File descriptor which was scanned.)
     @param(virname Virus name.)
     @param(context Opaque application provided data.) *)
  clcb_virus_found = procedure(fd: Integer; const virname: PChar; context: Pointer); cdecl;

  (* Signature-load callback.
     May be used to ignore signatures at database load time.
     
     WARNING: Some signatures (notably ldb, cbc) can be dependent upon other signatures.
     Failure to preserve dependency chains will result in database loading failure.
     It is the implementor's responsibility to guarantee consistency.
     @param(type The signature type (e.g. "db", "ndb", "mdb", etc.))
     @param(name Signature name.)
     @param(custom The signature is official (custom == 0) or custom (custom != 0))
     @param(context Opaque application provided data)
     @returns(0 to load the current signature.)
     @returns(Non-0 to skip the current signature.) *)
  clcb_sigload = function(const _type: PChar; const name: PChar; custom: Cardinal; context: Pointer): Integer; cdecl;

  cl_msg = (
    (* verbose *)
    CL_MSG_INFO_VERBOSE = 32,
    (* LibClamAV WARNING: *)
    CL_MSG_WARN = 64,
    (* LibClamAV ERROR: *)
    CL_MSG_ERROR = 128);
  Pcl_msg = ^cl_msg;

  (* Logging message callback for info, warning, and error messages.
     The specified callback will be called instead of logging to stderr.
     Messages of lower severity than specified are logged as usual.
     
     Callback may be used to silence logging by assigning a do-nothing function.
     Does not affect debug log messages.
     
     Just like with cl_debug() this must be called before going multithreaded.
     Callable before cl_init, if you want to log messages from cl_init() itself.
     
     You can use context of cl_scandesc_callback to convey more information to
     the callback (such as the filename!).
     
     Note: setting a 2nd callbacks overwrites previous, multiple callbacks are not
     supported.
     @param(severity Message severity (CL_MSG_INFO_VERBOSE, CL_MSG_WARN, or CL_MSG_ERROR).)
     @param(fullmsg The log message including the "LibClamAV <severity>: " prefix.)
     @param(msg The log message.)
     @param(context Opaque application provided data.) *)
  clcb_msg = procedure(severity: cl_msg; const fullmsg: PChar; const msg: PChar; context: Pointer); cdecl;

  (* LibClamAV hash stats callback.
     Callback that provides the hash of a scanned sample if a signature alerted.
     Provides a mechanism to record detection statistics.
     @param(fd File descriptor if available, else -1.)
     @param(size Sample size)
     @param(md5 Sample md5 hash)
     @param(virname Signature name that the sample matched against)
     @param(context Opaque application provided data) *)
  clcb_hash = procedure(fd: Integer; size: UInt64; const md5: PByte; const virname: PChar; context: Pointer); cdecl;

  (* Archive meta matching callback function.
     May be used to blacklist archive/container samples based on archive metadata.
     Function is invoked multiple times per archive. Typically once per contained file.
     
     Note: Used by the --archive-verbose clamscan option. Overriding this will alter
     the output from --archive-verbose.
     @param(container_type String name of type (CL_TYPE).)
     @param(fsize_container Sample size)
     @param(filename Filename associated with the data in archive.)
     @param(fsize_real Size of file after decompression (according to the archive).)
     @param(is_encrypted Boolean non-zero if the contained file is encrypted.)
     @param(filepos_container File index in container.)
     @param(context Opaque application provided data.)
     @returns(CL_VIRUS to blacklist)
     @returns(CL_CLEAN to continue scanning) *)
  clcb_meta = function(const container_type: PChar; fsize_container: Cardinal; const filename: PChar; fsize_real: Cardinal; is_encrypted: Integer; filepos_container: Cardinal; context: Pointer): cl_error_t; cdecl;

  (* File properties callback function.
     Invoked after a scan the CL_SCAN_GENERAL_COLLECT_METADATA general scan option
     is enabled and libclamav was built with json support.
     @param(j_propstr File properties/metadata in a JSON encoded string.)
     @param(rc The cl_error_t return code from the scan.)
     @param(cbdata Opaque application provided data.) *)
  clcb_file_props = function(const j_propstr: PChar; rc: Integer; cbdata: Pointer): Integer; cdecl;

  (* Add sample metadata to the statistics for a sample that matched on a signature.
     @param(virname Name of the signature that matched.)
     @param(md5 Sample hash.)
     @param(size Sample size.)
     @param(sections PE section data, if applicable.)
     @param(cbdata The statistics data. Probably a pointer to a malloc'd struct.) *)
  clcb_stats_add_sample = procedure(const virname: PChar; const md5: PByte; size: NativeUInt; sections: Pstats_section_t; cbdata: Pointer); cdecl;

  (* Remove a specific sample from the statistics report.
     @param(virname Name of the signature that matched.)
     @param(md5 Sample hash.)
     @param(size Sample size.)
     @param(cbdata The statistics data. Probably a pointer to a malloc'd struct.) *)
  clcb_stats_remove_sample = procedure(const virname: PChar; const md5: PByte; size: NativeUInt; cbdata: Pointer); cdecl;

  (* Decrement the hit count listed in the statistics report for a specific sample.
     @param(virname Name of the signature that matched.)
     @param(md5 Sample hash.)
     @param(size Sample size.)
     @param(cbdata The statistics data. Probably a pointer to a malloc'd struct.) *)
  clcb_stats_decrement_count = procedure(const virname: PChar; const md5: PByte; size: NativeUInt; cbdata: Pointer); cdecl;

  (* Function to submit a statistics report.
     @param(engine The initialized scanning engine.)
     @param(cbdata The statistics data. Probably a pointer to a malloc'd struct.) *)
  clcb_stats_submit = procedure(engine: Pcl_engine; cbdata: Pointer); cdecl;

  (* Function to flush/free the statistics report data.
     @param(engine The initialized scanning engine.)
     @param(cbdata The statistics data. Probably a pointer to a malloc'd struct.) *)
  clcb_stats_flush = procedure(engine: Pcl_engine; cbdata: Pointer); cdecl;

  (* Function to get the number of samples listed in the statistics report.
     @param(cbdata The statistics data. Probably a pointer to a malloc'd struct.) *)
  clcb_stats_get_num = function(cbdata: Pointer): NativeUInt; cdecl;

  (* Function to get the size of memory used to store the statistics report.
     @param(cbdata The statistics data. Probably a pointer to a malloc'd struct.) *)
  clcb_stats_get_size = function(cbdata: Pointer): NativeUInt; cdecl;

  (* Function to get the machine's unique host ID.
     @param(cbdata The statistics data. Probably a pointer to a malloc'd struct.) *)
  clcb_stats_get_hostid = function(cbdata: Pointer): PChar; cdecl;


  (* CVD / database functions *)
  cl_cvd = record
    time: PChar;
    version: Cardinal;
    sigs: Cardinal;
    fl: Cardinal;
    md5: PChar;
    dsig: PChar;
    builder: PChar;
    stime: Cardinal;
  end;


  (* DB directory stat functions.
     Use these functions to watch for database changes. *)
  cl_stat = record
    dir: PChar;
    stattab: Pstat;
    statdname: PPChar;
    entries: Cardinal;
  end;

  Pcl_fmap_t = Pointer;
  PPcl_fmap_t = ^Pcl_fmap_t;

  Poff_t = function(): Integer; cdecl;

(* Enable debug messages *)
procedure cl_debug(); cdecl; external cDllName;

(* Set libclamav to always create section hashes for PE files. Section hashes are used in .mdb signature. *)
procedure cl_always_gen_section_hash(); cdecl; external cDllName;

(* This function initializes the openssl crypto system.
   Called by cl_init() and does not need to be cleaned up as de-init
   is handled automatically by openssl 1.0.2.h and 1.1.0
   @returns(Always returns 0) *)
function cl_initialize_crypto(): Integer; cdecl; external cDllName;

(* This is a deprecated function that used to clean up ssl crypto inits.
   Call to EVP_cleanup() has been removed since cleanup is now handled by
   auto-deinit as of openssl 1.0.2h and 1.1.0 *)
procedure cl_cleanup_crypto(); cdecl;
  external cDllName;

(* Initialize the ClamAV library.
   @param(initoptions Unused.)
   @returns(cl_error_t   CL_SUCCESS if everything initalized correctly.) *)
function cl_init(initoptions: Cardinal): cl_error_t; cdecl;
  external cDllName;

(* Allocate a new scanning engine and initialize default settings.
   The engine should be freed with `cl_engine_free()`.
   @returns(struct cl_engine* Pointer to the scanning engine.) *)
function cl_engine_new(): Pcl_engine; cdecl;
  external cDllName;

(* Set a numerical engine option.
   Caution: changing options for an engine that is in-use is not thread-safe!
   @param(engine An initialized scan engine.)
   @param(cl_engine_field A CL_ENGINE option.)
   @param(num The new engine option value.)
   @returns(cl_error_t       CL_SUCCESS if successfully set.)
   @returns(cl_error_t       CL_EARG if the field number was incorrect.)
   @returns(cl_error_t       CL_ENULLARG null arguments were provided.) *)
function cl_engine_set_num(engine: Pcl_engine; field: cl_engine_field; num: Int64): cl_error_t; cdecl;
  external cDllName;

(* Get a numerical engine option.
   @param(engine An initialized scan engine.)
   @param(cl_engine_field A CL_ENGINE option.)
   @param(err (optional) A cl_error_t status code.)
   @returns(long long        The numerical option value.) *)
function cl_engine_get_num(const engine: Pcl_engine; field: cl_engine_field; err: PInteger): Int64; cdecl;
  external cDllName;

(* Set a string engine option.
   If the string option has already been set, the existing string will be free'd
   and the new string will replace it.
   
   Caution: changing options for an engine that is in-use is not thread-safe!
   @param(engine An initialized scan engine.)
   @param(cl_engine_field A CL_ENGINE option.)
   @param(str The new engine option value.)
   @returns(cl_error_t       CL_SUCCESS if successfully set.)
   @returns(cl_error_t       CL_EARG if the field number was incorrect.)
   @returns(cl_error_t       CL_EMEM if a memory allocation error occurred.)
   @returns(cl_error_t       CL_ENULLARG null arguments were provided.) *)
function cl_engine_set_str(engine: Pcl_engine; field: cl_engine_field; const str: PChar): cl_error_t; cdecl;
  external cDllName;

(* Get a string engine option.
   @param(engine An initialized scan engine.)
   @param(cl_engine_field A CL_ENGINE option.)
   @param(err (optional) A cl_error_t status code.)
   @returns(const char *     The string option value.) *)
function cl_engine_get_str(const engine: Pcl_engine; field: cl_engine_field; err: PInteger): PChar; cdecl;
  external cDllName;

(* Copy the settings from an existing scan engine.
   The cl_settings pointer is allocated and must be freed with cl_engine_settings_free().
   @param(engine An configured scan engine.)
   @returns(struct cl_settings*  The settings.) *)
function cl_engine_settings_copy(const engine: Pcl_engine): Pcl_settings; cdecl;
  external cDllName;

(* Apply settings from a settings structure to a scan engine.
   Caution: changing options for an engine that is in-use is not thread-safe!
   @param(engine A scan engine.)
   @param(settings The settings.)
   @returns(cl_error_t   CL_SUCCESS if successful.)
   @returns(cl_error_t   CL_EMEM if a memory allocation error occurred.) *)
function cl_engine_settings_apply(engine: Pcl_engine; const settings: Pcl_settings): cl_error_t; cdecl;
  external cDllName;

(* Free a settings struct pointer.
   @param(settings The settings struct pointer.)
   @returns(cl_error_t   CL_SUCCESS if successful.)
   @returns(cl_error_t   CL_ENULLARG null arguments were provided.) *)
function cl_engine_settings_free(settings: Pcl_settings): cl_error_t; cdecl;
  external cDllName;

(* Prepare the scanning engine.
   Called this after all required databases have been loaded and settings have
   been applied.
   @param(engine A scan engine.)
   @returns(cl_error_t   CL_SUCCESS if successful.)
   @returns(cl_error_t   CL_ENULLARG null arguments were provided.) *)
function cl_engine_compile(engine: Pcl_engine): cl_error_t; cdecl;
  external cDllName;

(* Add a reference count to the engine.
   Thread safety mechanism so that the engine is not free'd by another thread.
   
   The engine is initialized with refcount = 1, so this only needs to be called
   for additional scanning threads.
   @param(engine A scan engine.)
   @returns(cl_error_t   CL_SUCCESS if successful.)
   @returns(cl_error_t   CL_ENULLARG null arguments were provided.) *)
function cl_engine_addref(engine: Pcl_engine): cl_error_t; cdecl;
  external cDllName;

(* Free an engine.
   Will lower the reference count on an engine. If the reference count hits
   zero, the engine will be freed.
   @param(engine A scan engine.)
   @returns(cl_error_t   CL_SUCCESS if successful.)
   @returns(cl_error_t   CL_ENULLARG null arguments were provided.) *)
function cl_engine_free(engine: Pcl_engine): cl_error_t; cdecl;
  external cDllName;

(* Set a custom pre-cache callback function.
   Caution: changing options for an engine that is in-use is not thread-safe!
   @param(engine The initialized scanning engine.)
   @param(callback The callback function pointer.) *)
procedure cl_engine_set_clcb_pre_cache(engine: Pcl_engine; callback: clcb_pre_cache); cdecl;
  external cDllName;

(* Set a custom pre-scan callback function.
   Caution: changing options for an engine that is in-use is not thread-safe!
   @param(engine The initialized scanning engine.)
   @param(callback The callback function pointer.) *)
procedure cl_engine_set_clcb_pre_scan(engine: Pcl_engine; callback: clcb_pre_scan); cdecl;
  external cDllName;

(* Set a custom post-scan callback function.
   Caution: changing options for an engine that is in-use is not thread-safe!
   @param(engine The initialized scanning engine.)
   @param(callback The callback function pointer.) *)
procedure cl_engine_set_clcb_post_scan(engine: Pcl_engine; callback: clcb_post_scan); cdecl;
  external cDllName;

(* Set a custom virus-found callback function.
   Caution: changing options for an engine that is in-use is not thread-safe!
   @param(engine The initialized scanning engine.)
   @param(callback The callback function pointer.) *)
procedure cl_engine_set_clcb_virus_found(engine: Pcl_engine; callback: clcb_virus_found); cdecl;
  external cDllName;

(* Set a custom signature-load callback function.
   Caution: changing options for an engine that is in-use is not thread-safe!
   @param(engine The initialized scanning engine.)
   @param(callback The callback function pointer.)
   @param(context Opaque application provided data.) *)
procedure cl_engine_set_clcb_sigload(engine: Pcl_engine; callback: clcb_sigload; context: Pointer); cdecl;
  external cDllName;

(* Set a custom logging message callback function for all of libclamav.
   @param(callback The callback function pointer.) *)
procedure cl_set_clcb_msg(callback: clcb_msg); cdecl;
  external cDllName;

(* Set a custom hash stats callback function.
   Caution: changing options for an engine that is in-use is not thread-safe!
   @param(engine The initialized scanning engine.)
   @param(callback The callback function pointer.) *)
procedure cl_engine_set_clcb_hash(engine: Pcl_engine; callback: clcb_hash); cdecl;
  external cDllName;

(* Set a custom archive metadata matching callback function.
   Caution: changing options for an engine that is in-use is not thread-safe!
   @param(engine The initialized scanning engine.)
   @param(callback The callback function pointer.) *)
procedure cl_engine_set_clcb_meta(engine: Pcl_engine; callback: clcb_meta); cdecl;
  external cDllName;

(* Set a custom file properties callback function.
   Caution: changing options for an engine that is in-use is not thread-safe!
   @param(engine The initialized scanning engine.)
   @param(callback The callback function pointer.) *)
procedure cl_engine_set_clcb_file_props(engine: Pcl_engine; callback: clcb_file_props); cdecl;
  external cDllName;

(* Set a pointer the caller-defined cbdata structure.
   The data must persist at least until `clcb_stats_submit()` is called, or
   `clcb_stats_flush()` is called (optional).
   
   Caution: changing options for an engine that is in-use is not thread-safe!
   @param(engine The scanning engine.)
   @param(cbdata The statistics data. Probably a pointer to a malloc'd struct.) *)
procedure cl_engine_set_stats_set_cbdata(engine: Pcl_engine; cbdata: Pointer); cdecl;
  external cDllName;

(* Set a custom callback function to add sample metadata to a statistics report.
   Caution: changing options for an engine that is in-use is not thread-safe!
   @param(engine The initialized scanning engine.)
   @param(callback The callback function pointer.) *)
procedure cl_engine_set_clcb_stats_add_sample(engine: Pcl_engine; callback: clcb_stats_add_sample); cdecl;
  external cDllName;

(* Set a custom callback function to remove sample metadata from a statistics report.
   Caution: changing options for an engine that is in-use is not thread-safe!
   @param(engine The initialized scanning engine.)
   @param(callback The callback function pointer.) *)
procedure cl_engine_set_clcb_stats_remove_sample(engine: Pcl_engine; callback: clcb_stats_remove_sample); cdecl;
  external cDllName;

(* Set a custom callback function to decrement the hit count listed in the statistics report for a specific sample.
   This function may remove the sample from the report if the hit count is decremented to 0.
   @param(engine The initialized scanning engine.)
   @param(callback The callback function pointer.) *)
procedure cl_engine_set_clcb_stats_decrement_count(engine: Pcl_engine; callback: clcb_stats_decrement_count); cdecl;
  external cDllName;

(* Set a custom callback function to submit the statistics report.
   Caution: changing options for an engine that is in-use is not thread-safe!
   @param(engine The initialized scanning engine.)
   @param(callback The callback function pointer.) *)
procedure cl_engine_set_clcb_stats_submit(engine: Pcl_engine; callback: clcb_stats_submit); cdecl;
  external cDllName;

(* Set a custom callback function to flush/free the statistics report data.
   Caution: changing options for an engine that is in-use is not thread-safe!
   @param(engine The initialized scanning engine.)
   @param(callback The callback function pointer.) *)
procedure cl_engine_set_clcb_stats_flush(engine: Pcl_engine; callback: clcb_stats_flush); cdecl;
  external cDllName;

(* Set a custom callback function to get the number of samples listed in the statistics report.
   Caution: changing options for an engine that is in-use is not thread-safe!
   @param(engine The initialized scanning engine.)
   @param(callback The callback function pointer.) *)
procedure cl_engine_set_clcb_stats_get_num(engine: Pcl_engine; callback: clcb_stats_get_num); cdecl;
  external cDllName;

(* Set a custom callback function to get the size of memory used to store the statistics report.
   Caution: changing options for an engine that is in-use is not thread-safe!
   @param(engine The initialized scanning engine.)
   @param(callback The callback function pointer.) *)
procedure cl_engine_set_clcb_stats_get_size(engine: Pcl_engine; callback: clcb_stats_get_size); cdecl;
  external cDllName;

(* Set a custom callback function to get the machine's unique host ID.
   Caution: changing options for an engine that is in-use is not thread-safe!
   @param(engine The initialized scanning engine.)
   @param(callback The callback function pointer.) *)
procedure cl_engine_set_clcb_stats_get_hostid(engine: Pcl_engine; callback: clcb_stats_get_hostid); cdecl;
  external cDllName;

(* Function enables the built-in statistics reporting feature.
   @param(engine The initialized scanning engine.) *)
procedure cl_engine_stats_enable(engine: Pcl_engine); cdecl;
  external cDllName;

(* Scan a file, given a file descriptor.
   @param(desc File descriptor of an open file. The caller must provide this or the map.)
   @param(filename (optional) Filepath of the open file descriptor or file map.)
   @param(virname [out] Will be set to a statically allocated (i.e. needs not be freed) signature name if the scan matches against a signature.)
   @param(scanned [out] The number of bytes scanned.)
   @param(engine The scanning engine.)
   @param(scanoptions Scanning options.)
   @returns(cl_error_t       CL_CLEAN, CL_VIRUS, or an error code if an error occured during the scan.) *)
function cl_scandesc(desc: Integer; const filename: PChar; virname: PPChar; scanned: PCardinal; const engine: Pcl_engine; scanoptions: Pcl_scan_options): cl_error_t; cdecl;
  external cDllName;

(* Scan a file, given a file descriptor.
   This callback variant allows the caller to provide a context structure that caller provided callback functions can interpret.
   @param(desc File descriptor of an open file. The caller must provide this or the map.)
   @param(filename (optional) Filepath of the open file descriptor or file map.)
   @param(virname [out] Will be set to a statically allocated (i.e. needs not be freed) signature name if the scan matches against a signature.)
   @param(scanned [out] The number of bytes scanned.)
   @param(engine The scanning engine.)
   @param(scanoptions Scanning options.)
   @param(context [in] An opaque context structure allowing the caller to record details about the sample being scanned.)
   @returns(cl_error_t       CL_CLEAN, CL_VIRUS, or an error code if an error occured during the scan.) *)
function cl_scandesc_callback(desc: Integer; const filename: PChar; virname: PPChar; scanned: PCardinal; const engine: Pcl_engine; scanoptions: Pcl_scan_options; context: Pointer): cl_error_t; cdecl;
  external cDllName;

(* Scan a file, given a filename.
   @param(filename Filepath of the file to be scanned.)
   @param(virname [out] Will be set to a statically allocated (i.e. needs not be freed) signature name if the scan matches against a signature.)
   @param(scanned [out] The number of bytes scanned.)
   @param(engine The scanning engine.)
   @param(scanoptions Scanning options.)
   @returns(cl_error_t       CL_CLEAN, CL_VIRUS, or an error code if an error occured during the scan.) *)
function cl_scanfile(const filename: PChar; virname: PPChar; scanned: PCardinal; const engine: Pcl_engine; scanoptions: Pcl_scan_options): cl_error_t; cdecl;
  external cDllName;

(* Scan a file, given a filename.
   This callback variant allows the caller to provide a context structure that caller provided callback functions can interpret.
   @param(filename Filepath of the file to be scanned.)
   @param(virname [out] Will be set to a statically allocated (i.e. needs not be freed) signature name if the scan matches against a signature.)
   @param(scanned [out] The number of bytes scanned.)
   @param(engine The scanning engine.)
   @param(scanoptions Scanning options.)
   @param(context [in] An opaque context structure allowing the caller to record details about the sample being scanned.)
   @returns(cl_error_t       CL_CLEAN, CL_VIRUS, or an error code if an error occured during the scan.) *)
function cl_scanfile_callback(const filename: PChar; virname: PPChar; scanned: PCardinal; const engine: Pcl_engine; scanoptions: Pcl_scan_options; context: Pointer): cl_error_t; cdecl;
  external cDllName;


(* Database handling. *)
function cl_load(const path: PChar; engine: Pcl_engine; signo: PCardinal; dboptions: Cardinal): cl_error_t; cdecl;
  external cDllName;

function cl_retdbdir(): PChar; cdecl;
  external cDllName;

(* Read the CVD header data from a file.
   The returned pointer must be free'd with cl_cvdfree().
   @param(file Filepath of CVD file.)
   @returns(struct cl_cvd*   Pointer to an allocated CVD header data structure.) *)
function cl_cvdhead(const _file: PChar): Pcl_cvd; cdecl;
  external cDllName;

(* Parse the CVD header.
   Buffer length is not an argument, and the check must be done
   by the caller cl_cvdhead().
   
   The returned pointer must be free'd with cl_cvdfree().
   @param(head Pointer to the header data buffer.)
   @returns(struct cl_cvd*   Pointer to an allocated CVD header data structure.) *)
function cl_cvdparse(const head: PChar): Pcl_cvd; cdecl;
  external cDllName;

(* Verify a CVD file by loading and unloading it.
   @param(file Filepath of CVD file.)
   @returns(cl_error_t   CL_SUCCESS if success, else a CL_E* error code.) *)
function cl_cvdverify(const _file: PChar): cl_error_t; cdecl;
  external cDllName;

(* Free a CVD header struct.
   @param(cvd Pointer to a CVD header struct.) *)
procedure cl_cvdfree(cvd: Pcl_cvd); cdecl;
  external cDllName;

(* Initialize a directory to be watched for database changes.
   The dbstat out variable is allocated and must be freed using cl_statfree().
   @param(dirname Pathname of the database directory.)
   @param(dbstat [out] dbstat handle.)
   @returns(cl_error_t   CL_SUCCESS if successfully initialized.) *)
function cl_statinidir(const dirname: PChar; dbstat: Pcl_stat): cl_error_t; cdecl; external cDllName;

(* Check the database directory for changes.
   @param(dbstat dbstat handle.)
   @returns(int   0 No change.)
   @returns(int   1 Some change occured.) *)
function cl_statchkdir(const dbstat: Pcl_stat): Integer; cdecl; external cDllName;

(* Free the dbstat handle.
   @param(dbstat dbstat handle.)
   @returns(cl_error_t   CL_SUCCESS)
   @returns(cl_error_t   CL_ENULLARG) *)
function cl_statfree(dbstat: Pcl_stat): cl_error_t; cdecl; external cDllName;

(* Count the number of signatures in a database file or directory.
   @param(path Path of the database file or directory.)
   @param(countoptions A bitflag field. May be CL_COUNTSIGS_OFFICIAL, CL_COUNTSIGS_UNOFFICIAL, or CL_COUNTSIGS_ALL.)
   @param(sigs [out] The number of sigs.)
   @returns(cl_error_t   CL_SUCCESS if success, else a CL_E* error type.) *)
function cl_countsigs(const path: PChar; countoptions: Cardinal; sigs: PCardinal): cl_error_t; cdecl; external cDllName;

(* Get the Functionality Level (FLEVEL).
   @returns(unsigned int The FLEVEL.) *)
function cl_retflevel(): Cardinal; cdecl; external cDllName;

(* Get the ClamAV version string.
   E.g. clamav-0.100.0-beta
   @returns(const char* The version string.) *)
function cl_retver(): PChar; cdecl; external cDllName;

(* Others. *)
function cl_strerror(clerror: Integer): PChar; cdecl; external cDllName;

function cl_fmap_open_handle(handle: Pointer; offset: NativeUInt; len: NativeUInt; pread_cb: Integer; use_aging: Integer): Pcl_fmap_t; cdecl; external cDllName;

(* Open a map given a buffer.
   Open a map for scanning custom data, where the data is already in memory,
   either in the form of a buffer, a memory mapped file, etc.
   Note that the memory [start, start+len) must be the _entire_ file,
   you can't give it parts of a file and expect detection to work.
   @param(start Pointer to a buffer of data.)
   @param(len Length in bytes of the data.)
   @returns(cl_fmap_t*   A map representing the buffer.) *)
function cl_fmap_open_memory(const start: Pointer; len: NativeUInt): Pcl_fmap_t; cdecl; external cDllName;

(* Releases resources associated with the map.
   You should release any resources you hold only after (handles, maps) calling
   this function.
   @param(map Map to be closed.) *)
procedure cl_fmap_close(p1: Pcl_fmap_t); cdecl; external cDllName;

(* Scan custom data.
   @param(map Buffer to be scanned, in form of a cl_fmap_t.)
   @param(filename Name of data origin. Does not need to be an actual
     file on disk. May be NULL if a name is not available.)
   @param(virname [out] Pointer to receive the signature match name name if a
     signature matched.)
   @param(scanned [out] Number of bytes scanned.)
   @param(engine The scanning engine.)
   @param(scanoptions The scanning options struct.)
   @param(context An application-defined context struct, opaque to
     libclamav. May be used within your callback functions.)
   @returns(cl_error_t   CL_CLEAN if no signature matched. CL_VIRUS if a
     signature matched. Another CL_E* error code if an
     error occured.) *)
function cl_scanmap_callback(map: Pcl_fmap_t; const filename: PChar; virname: PPChar; scanned: PCardinal; const engine: Pcl_engine; scanoptions: Pcl_scan_options; context: Pointer): cl_error_t; cdecl; external cDllName;

(* Generate a hash of data.
   @param(alg The hashing algorithm to use.)
   @param(buf The data to be hashed.)
   @param(len The length of the to-be-hashed data.)
   @param(obuf [out] (optional) A buffer to store the generated hash. Use NULL to dynamically allocate buffer.)
   @param(olen [out] (optional) A pointer that stores how long the generated hash is.)
   @returns(A pointer to the generated hash or obuf if obuf is not NULL.) *)
function cl_hash_data(const alg: PChar; const buf: Pointer; len: NativeUInt; obuf: PByte; olen: PCardinal): PByte; cdecl; external cDllName;

function cl_hash_file_fd_ctx(ctx: PInteger; fd: Integer; olen: PCardinal): PByte; cdecl; external cDllName;

(* Generate a hash of a file.
   @param(fd The file descriptor.)
   @param(alg The hashing algorithm to use.)
   @param(olen [out] (optional) The length of the generated hash.)
   @returns(A pointer to a malloc'd buffer that holds the generated hash.) *)
function cl_hash_file_fd(fd: Integer; const alg: PChar; olen: PCardinal): PByte; cdecl; external cDllName;

function cl_hash_file_fp(fp: PInteger; const alg: PChar; olen: PCardinal): PByte; cdecl; external cDllName;

(* Generate a sha256 hash of data.
   @param(buf The data to hash.)
   @param(len The length of the to-be-hashed data.)
   @param(obuf [out] (optional) A pointer to store the generated hash. Use NULL to dynamically allocate buffer.)
   @param(olen [out] (optional) The length of the generated hash.)
   @returns(A pointer to a malloc'd buffer that holds the generated hash.) *)
function cl_sha256(const buf: Pointer; len: NativeUInt; obuf: PByte; olen: PCardinal): PByte; cdecl; external cDllName;

(* Generate a sha384 hash of data.
   @param(buf The data to hash.)
   @param(len The length of the to-be-hashed data.)
   @param(obuf [out] (optional) A pointer to store the generated hash. Use NULL to dynamically allocate buffer.)
   @param(olen [out] (optional) The length of the generated hash.)
   @returns(A pointer to a malloc'd buffer that holds the generated hash.) *)
function cl_sha384(const buf: Pointer; len: NativeUInt; obuf: PByte; olen: PCardinal): PByte; cdecl; external cDllName;

(* Generate a sha512 hash of data.
   @param(buf The data to hash.)
   @param(len The length of the to-be-hashed data.)
   @param(obuf [out] (optional) A pointer to store the generated hash. Use NULL to dynamically allocate buffer.)
   @param(olen [out] (optional) The length of the generated hash.)
   @returns(A pointer to a malloc'd buffer that holds the generated hash.) *)
function cl_sha512(const buf: Pointer; len: NativeUInt; obuf: PByte; olen: PCardinal): PByte; cdecl; external cDllName;

(* Generate a sha1 hash of data.
   @param(buf The data to hash.)
   @param(len The length of the to-be-hashed data.)
   @param(obuf [out] (optional) A pointer to store the generated hash. Use NULL to dynamically allocate buffer.)
   @param(olen [out] (optional) The length of the generated hash.)
   @returns(A pointer to a malloc'd buffer that holds the generated hash.) *)
function cl_sha1(const buf: Pointer; len: NativeUInt; obuf: PByte; olen: PCardinal): PByte; cdecl;
  external cDllName;

function cl_verify_signature(pkey: PInteger; const alg: PChar; sig: PByte; siglen: Cardinal; data: PByte; datalen: NativeUInt; decode: Integer): Integer; cdecl; external cDllName;

function cl_verify_signature_hash(pkey: PInteger; const alg: PChar; sig: PByte; siglen: Cardinal; digest: PByte): Integer; cdecl;
  external cDllName;

function cl_verify_signature_fd(pkey: PInteger; const alg: PChar; sig: PByte; siglen: Cardinal; fd: Integer): Integer; cdecl; external cDllName;

(* Verify validity of signed data.
   @param(x509path The path to the public key of the keypair that signed the data.)
   @param(alg The algorithm used to hash the data.)
   @param(sig The signature block.)
   @param(siglen The length of the signature.)
   @param(digest The hash of the signed data.)
   @returns(0 for success, -1 for error or invalid signature.) *)
function cl_verify_signature_hash_x509_keyfile(x509path: PChar; const alg: PChar; sig: PByte; siglen: Cardinal; digest: PByte): Integer; cdecl; external cDllName;

(* Verify validity of signed data.
   @param(x509path The path to the public key of the keypair that signed the data.)
   @param(alg The algorithm used to hash the data.)
   @param(sig The signature block.)
   @param(siglen The length of the signature.)
   @param(fd The file descriptor.)
   @returns(0 for success, -1 for error or invalid signature.) *)
function cl_verify_signature_fd_x509_keyfile(x509path: PChar; const alg: PChar; sig: PByte; siglen: Cardinal; fd: Integer): Integer; cdecl; external cDllName;

(* Verify validity of signed data.
   @param(x509path The path to the public key of the keypair that signed the data.)
   @param(alg The algorithm used to hash the data.)
   @param(sig The signature block.)
   @param(siglen The length of the signature.)
   @param(data The data that was signed.)
   @param(datalen The length of the data.)
   @param(decode Whether or not to base64-decode the signature prior to verification. 1 for yes, 0 for no.)
   @returns(0 for success, -1 for error or invalid signature.) *)
function cl_verify_signature_x509_keyfile(x509path: PChar; const alg: PChar; sig: PByte; siglen: Cardinal; data: PByte; datalen: NativeUInt; decode: Integer): Integer; cdecl; external cDllName;

function cl_verify_signature_hash_x509(x509: PInteger; const alg: PChar; sig: PByte; siglen: Cardinal; digest: PByte): Integer; cdecl; external cDllName;

function cl_verify_signature_fd_x509(x509: PInteger; const alg: PChar; sig: PByte; siglen: Cardinal; fd: Integer): Integer; cdecl; external cDllName;

function cl_verify_signature_x509(x509: PInteger; const alg: PChar; sig: PByte; siglen: Cardinal; data: PByte; datalen: NativeUInt; decode: Integer): Integer; cdecl; external cDllName;

function cl_get_x509_from_mem(): PInteger; cdecl; external cDllName;

(* Validate an X509 certificate chain, with the chain being located in a directory.
   @param(tsdir The path to the trust store directory.)
   @param(certpath The path to the X509 certificate to be validated.)
   @returns(0 for success, -1 for error or invalid certificate.) *)
function cl_validate_certificate_chain_ts_dir(tsdir: PChar; certpath: PChar): Integer; cdecl; external cDllName;

(* Validate an X509 certificate chain with support for a CRL.
   @param(authorities A NULL-terminated array of strings that hold the path of the CA's X509 certificate.)
   @param(crlpath (optional) A path to the CRL file. NULL if no CRL.)
   @param(certpath The path to the X509 certificate to be validated.)
   @returns(0 for success, -1 for error or invalid certificate.) *)
function cl_validate_certificate_chain(authorities: PPChar; crlpath: PChar; certpath: PChar): Integer; cdecl; external cDllName;

function cl_load_cert(): PInteger; cdecl; external cDllName;

function cl_ASN1_GetTimeT(timeobj: PInteger): Ptm; cdecl; external cDllName;

function cl_load_crl(): PInteger; cdecl; external cDllName;

(* Sign data with a key stored on disk.
   @param(keypath The path to the RSA private key.)
   @param(alg The hash/signature algorithm to use.)
   @param(hash The hash to sign.)
   @param(olen [out] A pointer that stores the size of the signature.)
   @param(Whether or not to base64-encode the signature. 1 for yes, 0 for no.)
   @returns(The generated signature.) *)
function cl_sign_data_keyfile(keypath: PChar; const alg: PChar; hash: PByte; olen: PCardinal; encode: Integer): PByte; cdecl; external cDllName;

function cl_sign_data(pkey: PInteger; const alg: PChar; hash: PByte; olen: PCardinal; encode: Integer): PByte; cdecl; external cDllName;

function cl_sign_file_fd(fd: Integer; pkey: PInteger; const alg: PChar; olen: PCardinal; encode: Integer): PByte; cdecl; external cDllName;

function cl_sign_file_fp(fp: PInteger; pkey: PInteger; const alg: PChar; olen: PCardinal; encode: Integer): PByte; cdecl; external cDllName;

function cl_get_pkey_file(): PInteger; cdecl; external cDllName;

function cl_hash_init(const alg: PChar): Pointer; cdecl; external cDllName;

function cl_update_hash(ctx: Pointer; const data: Pointer; sz: NativeUInt): Integer; cdecl; external cDllName;

function cl_finish_hash(ctx: Pointer; buf: Pointer): Integer; cdecl; external cDllName;

procedure cl_hash_destroy(ctx: Pointer); cdecl; external cDllName;

implementation

end.
