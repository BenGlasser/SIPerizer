grammar SIP;
//   Several rules are incorporated from RFC 2396 [5] but are updated to
//   make them compliant with RFC 2234 [10].  These include:
      CR          : '\r';
      LF          : '\n';
      CRLF        : CR LF;
      DIGIT       : [0-9];
      SP          : ' ';
      HTAB        : '\t';
      WSP         : SP | HTAB;
      ALPHA       : [a-zA-Z]*;
      ALPHANUM    : [a-zA-Z0-9]*;
      alphanum    : ALPHANUM;


      reserved    :  ';'
                  |  '/'
                  |  '?'
                  |  ':'
                  |  '@'
                  |  '&'
                  |  '='
                  |  '+'
                  |  '$'
                  |  ','
                  ;

      unreserved  :  alphanum
                  |  mark
                  ;

      mark        :  '-'
                  |  '_'
                  |  '.'
                  |  '!'
                  |  '~'
                  |  '*'
                  |  '\''
                  |  '('
                  |  ')'
                  ;

      escaped     :  '%' HEXDIG HEXDIG;

//   SIP header field values can be folded onto multiple lines if the
//   continuation line begins with a space or horizontal tab.  All linear
//   white space, including folding, has the same semantics as SP.  A
//   recipient MAY replace any linear white space with a single SP before
//   interpreting the field value or forwarding the message downstream.
//   This is intended to behave exactly as HTTP/1.1 as described in RFC
//   2616 [8].  The SWS construct is used when linear white space is
//   optional, generally between tokens and separators.

      LWS  :  ((WSP)* CRLF)? WSP+ ; //linear whitespace
      SWS  :  (LWS)? ; //sep whitespace

//   To separate the header name from the rest of value, a colon is used,
//   which, by the above rule, allows whitespace before, but no line
//   break, and whitespace after, including a linebreak.  The HCOLON
//   defines this construct.

      HCOLON  :  ( SP | HTAB )* ':' SWS;

//  The TEXT-UTF8 rule is only used for descriptive field contents and
//   values that are not intended to be interpreted by the message parser.
//   Words of *TEXT-UTF8 contain characters from the UTF-8 charset (RFC
//   2279 [7]).  The TEXT_UTF8_TRIM rule is used for descriptive field
//  contents that are n t quoted strings, where leading and trailing LWS
//   is not meaningful.  In this regard, SIP differs from HTTP, which uses
//   the ISO 8859-1 character set.

      TEXT_UTF8_TRIM  :  TEXT_UTF8char+ (LWS* TEXT_UTF8char)*;
      TEXT_UTF8char   :  '\u0021'..'\u007E' | UTF8_NONASCII;
      UTF8_NONASCII   :  '\u00C0'..'\u00DF' UTF8_CONT{1}
                      |  '\u00E0'..'\u00EF' UTF8_CONT{2}
                      |  '\u00F0'..'\u00F7' UTF8_CONT{3}
                      |  '\u00F8'..'\u00FB' UTF8_CONT{4}
                      |  '\u00FC'..'\u00FD' UTF8_CONT{5}
                      ;
      UTF8_CONT       :  '\u0080'..'\u00BF';

//   A CRLF is allowed in the definition of TEXT_UTF8_TRIM only as part of
//   a header field continuation.  It is expected that the folding LWS
//   will be replaced with a single SP before interpretation of the TEXT-
//   UTF8-TRIM value.

//   Hexadecimal numeric characters are used in several protocol elements.
//   Some elements (authentication) force hex alphas to be lower case.

      LHEX  :  DIGIT | '\u0061'..'\u0066' ; //lowercase a-f

//   Many SIP header field values consist of words separated by LWS or
//   special characters.  Unless otherwise stated, tokens are case-
//   insensitive.  These special characters MUST be in a quoted string to
//   be used within a parameter value.  The word construct is used in
//   Call-ID to allow most separators to be used.

      token       :  (alphanum | '-' | '.' | '!' | '%' | '*'
                     | '_' | '+' | '`' | '\'' | '~' )+;
      separators  :  '(' | ')' | '<' | '>' | '@' |
                     ',' | ';' | ':' | '\\' | DQUOTE |
                     '/' | '[' | ']' | '?' | '=' |
                     '{' | '}' | SP | HTAB;
      word        :  (alphanum | '-' | '.' | '!' | '%' | '*' |
                     '_' | '+' | '`' | '\'' | '~' |
                     '(' | ')' | '<' | '>' |
                     ':' | '\\' | DQUOTE |
                     '/' | '[' | ']' | '?' |
                     '{' | '}' )+;

//   When tokens are used or separators are used between elements,
//   whitespace is often allowed before or after these characters:

      STAR    :  SWS '*' SWS ; //asterisk
      SLASH   :  SWS '/' SWS ; //slash
      EQUAL   :  SWS '=' SWS ; //equal
      LPAREN  :  SWS '(' SWS ; //left parenthesis
      RPAREN  :  SWS ')' SWS ; //right parenthesis
      RAQUOT  :  '>' SWS ; //right angle quote
      LAQUOT  :  SWS '<'; //left angle quote
      COMMA   :  SWS ',' SWS ; //comma
      SEMI    :  SWS ';' SWS ; //semicolon
      COLON   :  SWS ':' SWS ; //colon
      LDQUOT  :  SWS DQUOTE; //open double quotation mark
      RDQUOT  :  DQUOTE SWS ; //close double quotation mark

//   Comments can be included in some SIP header fields by surrounding the
//   comment text with parentheses.  Comments are only allowed in fields
//   containing 'comment' as part of their field value definition.  In all
//   other fields, parentheses are considered part of the field value.

      comment  :  LPAREN (ctext | quoted_pair | comment)* RPAREN;
      ctext    :  '\u0021'..'\u0027' | '\u002A'..'\u005B' | '\u005D'..'\u007E' | UTF8_NONASCII
               |  LWS
               ;

//   ctext includes all chars except left and right parens and backslash.
//   A string of text is parsed as a single word if it is quoted using
//   double-quote marks.  In quoted strings, quotation marks (') and
//   backslashes (\) need to be escaped.

      quoted_string  :  SWS DQUOTE (qdtext | quoted_pair )* DQUOTE;
      qdtext         :  LWS | '\u0021' | '\u0023'..'\u005B' | '\u005D'..'\u007E'
                     |  UTF8_NONASCII
                     ;

//   The backslash character ('\') MAY be used as a single-character
//   quoting mechanism only within quoted_string and comment constructs.
//   Unlike HTTP/1.1, the characters CR and LF cannot be escaped by this
//   mechanism to avoid conflict with line folding and header separation.

quoted_pair  :  '\\' ('\u0000'..'\u0009' | '\u000B'..'\u000C'
             |  '\u000E'..'\u007F');

SIP_URI          :  'sip:' ( userinfo )? hostport uri_parameters ( headers )?;
SIPS_URI         :  'sips:' ( userinfo )? hostport uri_parameters ( headers )?;
userinfo         :  ( user | telephone_subscriber ) ( ':' password )? '@';
user             :  ( unreserved | escaped | user_unreserved )+;
user_unreserved  :  '&' | '=' | '+' | '$' | ',' | ';' | '?' | '/';
password         :  ( unreserved | escaped | '&' | '=' | '+' | '$' | ',' )*;
hostport         :  host ( ':' port )?;
host             :  hostname | IPv4address | IPv6reference;
hostname         :  ( domainlabel '.' )* toplabel ( '.' )?;
domainlabel      :  alphanum | alphanum ( alphanum | '-' )* alphanum;
toplabel         :  ALPHA | ALPHA ( alphanum | '-' )* alphanum;

IPv4address    :  [\d]{1-3} '.' [\d]{1-3} '.' [\d]{1-3} '.' [\d]{1-3};
IPv6reference  :  '[' IPv6address ']';
IPv6address    :  hexpart ( ':' IPv4address )?;
hexpart        :  hexseq | hexseq '::' ( hexseq )? | '::' ( hexseq )?;
hexseq         :  hex4 ( ':' hex4)*;
hex4           :  HEXDIG{1-4};
port           :  DIGIT+;

   // The BNF for telephone_subscriber can be found in RFC 2806 [9].  Note,
   // however, that any characters allowed there that are not allowed in
   // the user part of the SIP URI MUST be escaped.

uri_parameters    :  ( ';' uri_parameter)*;

uri_parameter     :  transport_param
                  | user_param
                  | method_param
                  | ttl_param
                  | maddr_param
                  | lr_param
                  | other_param
                  ;

transport_param   :  'transport='
                     ( 'udp' | 'tcp' | 'sctp' | 'tls'
                     | other_transport);
other_transport   :  token;
user_param        :  'user=' ( 'phone' | 'ip' | other_user);
other_user        :  token;
method_param      :  'method=' Method;
ttl_param         :  'ttl=' ttl;
maddr_param       :  'maddr=' host;
lr_param          :  'lr';
other_param       :  pname ( '=' pvalue )?;
pname             :  paramchar+;
pvalue            :  paramchar+;
paramchar         :  param_unreserved | unreserved | escaped;
param_unreserved  :  '[' | ']' | '/' | ':' | '&' | '+' | '$';

headers         :  '?' header *( '&' header );
header          :  hname '=' hvalue;
hname           :  ( hnv_unreserved | unreserved | escaped )+;
hvalue          :  ( hnv_unreserved | unreserved | escaped )*;
hnv_unreserved  :  '[' | ']' | '/' | '?' | ':' | '+' | '$';

SIP_message    :  Request | Response;
Request        :  Request_Line
                  ( message_header )*
                  CRLF
                  ( message_body )?;
Request_Line   :  Method SP Request_URI SP SIP_Version CRLF;
Request_URI    :  SIP_URI | SIPS_URI | absoluteURI;
absoluteURI    :  scheme ':' ( hier_part | opaque_part );
hier_part      :  ( net_path | abs_path ) ( '?' query )?;
net_path       :  '//' authority ( abs_path )?;
abs_path       :  '/' path_segments;

opaque_part    :  uric_no_slash *uric;
uric           :  reserved | unreserved | escaped;
uric_no_slash  :  unreserved | escaped | ';' | '?' | ':' | '@'
                  | '&' | '=' | '+' | '$' | ',';
path_segments  :  segment *( '/' segment );
segment        :  pchar* ( ';' param )*;
param          :  pchar*;
pchar          :  unreserved | escaped /
                  ':' | '@' | '&' | '=' | '+' | '$' | ',';
scheme         :  ALPHA *( ALPHA | DIGIT | '+' | '-' | '.' );
authority      :  srvr | reg_name;
srvr           :  ( ( userinfo '@' )? hostport )?;
reg_name       :  ( unreserved | escaped | '$' | ','
                  | ';' | ':' | '@' | '&' | '=' | '+' )+;
query          :  uric*;
SIP_Version    :  'SIP' '/' DIGIT+ '.' DIGIT+;

message_header  :  (Accept
                |  Accept_Encoding
                |  Accept_Language
                |  Alert_Info
                |  Allow
                |  Authentication_Info
                |  Authorization
                |  Call_ID
                |  Call_Info
                |  Contact
                |  Content_Disposition
                |  Content_Encoding
                |  Content_Language
                |  Content_Length
                |  Content_Type
                |  CSeq
                |  Date
                |  Error_Info
                |  Expires
                |  From
                |  In_Reply_To
                |  Max_Forwards
                |  MIME_Version
                |  Min_Expires
                |  Organization
                |  Priority
                |  Proxy_Authenticate
                |  Proxy_Authorization
                |  Proxy_Require
                |  Record_Route
                |  Reply_To
                |  Require
                |  Retry_After
                |  Route
                |  Server
                |  Subject
                |  Supported
                |  Timestamp
                |  To
                |  Unsupported
                |  User_Agent
                |  Via
                |  Warning
                |  WWW_Authenticate
                |  extension_header) CRLF
                ;

INVITEm           :  '\u0049\u004E\u0056\u0049\u0054\u0045' ; // INVITE in caps;
ACKm              :  '\u0041\u0043\u004B' ; // ACK in caps;
OPTIONSm          :  '\u004F\u0050\u0054\u0049\u004F\u004E\u0053' ; // OPTIONS in caps
BYEm              :  '\u0042\u0059\u0045' ; // BYE in caps
CANCELm           :  '\u0043\u0041\u004E\u0043\u0045\u004C' ; //CANCEL in caps
REGISTERm         :  '\u0052\u0045\u0047\u0049\u0053\u0054\u0045\u0052' ; // REGISTER in caps

Method            :  INVITEm | ACKm | OPTIONSm | BYEm
                  |  CANCELm | REGISTERm
                  |  extension_method
                  ;

extension_method  :  token;
Response          :  Status_Line
                     *( message_header )
                     CRLF
                     ( message_body )?
                  ;

Status_Line     :  SIP_Version SP Status_Code SP Reason_Phrase CRLF;
Status_Code     :  Informational
                |   Redirection
                |   Success
                |   Client_Error
                |   Server_Error
                |   Global_Failure
                |   extension_code
                ;

extension_code  :  DIGIT{3};
Reason_Phrase   :  (reserved | unreserved | escaped
                   | UTF8_NONASCII | UTF8_CONT | SP | HTAB)*;

Informational  :   '100' //  Trying
               |   '180' //  Ringing
               |   '181' //  Call Is Being Forwarded
               |   '182' //  Queued
               |   '183' //  Session Progress
               ;

Success  :  '200'  ;  // OK

Redirection  :   '300'  //  Multiple Choices
             |   '301'  //  Moved Permanently
             |   '302'  //  Moved Temporarily
             |   '305'  //  Use Proxy
             |   '380'  //  Alternative Service
             ;

Client_Error  :   '400'  //  Bad Request
              |   '401'  //  Unauthorized
              |   '402'  //  Payment Required
              |   '403'  //  Forbidden
              |   '404'  //  Not Found
              |   '405'  //  Method Not Allowed
              |   '406'  //  Not Acceptable
              |   '407'  //  Proxy Authentication Required
              |   '408'  //  Request Timeout
              |   '410'  //  Gone
              |   '413'  //  Request Entity Too Large
              |   '414'  //  Request_URI Too Large
              |   '415'  //  Unsupported Media Type
              |   '416'  //  Unsupported URI Scheme
              |   '420'  //  Bad Extension
              |   '421'  //  Extension Required
              |   '423'  //  Interval Too Brief
              |   '480'  //  Temporarily not available
              |   '481'  //  Call Leg/Transaction Does Not Exist
              |   '482'  //  Loop Detected
              |   '483'  //  Too Many Hops
              |   '484'  //  Address Incomplete
              |   '485'  //  Ambiguous
              |   '486'  //  Busy Here
              |   '487'  //  Request Terminated
              |   '488'  //  Not Acceptable Here
              |   '491'  //  Request Pending
              |   '493'  //  Undecipherable
              ;

Server_Error  :  '500'  //  Internal Server Error
              |   '501'  //  Not Implemented
              |   '502'  //  Bad Gateway
              |   '503'  //  Service Unavailable
              |   '504'  //  Server Time_out
              |   '505'  //  SIP Version not supported
              |   '513'  //  Message Too Large
              ;









Global_Failure  :  '600'  //  Busy Everywhere
                |   '603'  //  Decline
                |   '604'  //  Does not exist anywhere
                |   '606'  //  Not Acceptable
                ;

Accept         :  'Accept' HCOLON
                   ( accept_range *(COMMA accept_range) )?;
accept_range   :  media_range *(SEMI accept_param);
media_range    :  ( '*/*'
                  | ( m_type SLASH '*' )
                  | ( m_type SLASH m_subtype )
                  ) *( SEMI m_parameter )
               ;

accept_param   :  ('q' EQUAL qvalue) | generic_param;
qvalue         :  ( '0' ( '.' DIGIT{0-3} )? )
                  | ( '1' ( '.' ('0'){0-3} )? )
               ;

generic_param  :  token ( EQUAL gen_value )?;
gen_value      :  token | host | quoted_string;

Accept_Encoding  :  'Accept_Encoding' HCOLON
                     ( encoding (COMMA encoding)* )?;
encoding         :  codings (SEMI accept_param)*;
codings          :  content_coding | '*';
content_coding   :  token;

Accept_Language  :  'Accept_Language' HCOLON
                     ( language (COMMA language)* )?;
language         :  language_range (SEMI accept_param)*;
language_range   :  ( ( ALPHA{1-8} ( '-' ALPHA{1-8} )* ) | '*' );

Alert_Info   :  'Alert_Info' HCOLON alert_param (COMMA alert_param)*;
alert_param  :  LAQUOT absoluteURI RAQUOT ( SEMI generic_param )*;

Allow  :  'Allow' HCOLON (Method (COMMA Method)*)?;

Authorization     :  'Authorization' HCOLON credentials;
credentials       :  ('Digest' LWS digest_response)
                  |  other_response
                  ;

digest_response   :  dig_resp (COMMA dig_resp)*;
dig_resp          :  username
                  |  realm
                  |  nonce
                  |  digest_uri
                  |  dresponse
                  |  algorithm
                  |  cnonce
                  |  opaque
                  |  message_qop
                  |  nonce_count
                  |  auth_param
                  ;

username          :  'username' EQUAL username_value;

username_value    :  quoted_string;
digest_uri        :  'uri' EQUAL LDQUOT digest_uri_value RDQUOT;
digest_uri_value  :  rquest_uri ; //Equal to Request_URI as specified by HTTP/1.1;
message_qop       :  'qop' EQUAL qop_value;






cnonce            :  'cnonce' EQUAL cnonce_value;
cnonce_value      :  nonce_value;
nonce_count       :  'nc' EQUAL nc_value;
nc_value          :  LHEX{8};
dresponse         :  'response' EQUAL request_digest;
request_digest    :  LDQUOT LHEX{32} RDQUOT;
auth_param        :  auth_param_name EQUAL
                     ( token | quoted_string )
                  ;

auth_param_name   :  token;
other_response    :  auth_scheme LWS auth_param
                     (COMMA auth_param)*;
auth_scheme       :  token;

Authentication_Info  :  'Authentication_Info' HCOLON ainfo
                        (COMMA ainfo)*;
ainfo                :  nextnonce
                     |  message_qop
                     |  response_auth
                     |  cnonce
                     |  nonce_count
                     ;

nextnonce            :  'nextnonce' EQUAL nonce_value;
response_auth        :  'rspauth' EQUAL response_digest;
response_digest      :  LDQUOT LHEX* RDQUOT;

Call_ID  :  ( 'Call-ID' | 'i' ) HCOLON callid;
callid   :  word ( '@' word )?;

Call_Info   :  'Call-Info' HCOLON info (COMMA info)*;
info        :  LAQUOT absoluteURI RAQUOT ( SEMI info_param)*;
info_param  :  ( 'purpose' EQUAL ( 'icon' | 'info'
               | 'card' | token ) )
            | generic_param
            ;

Contact        :  ('Contact' | 'm' ) HCOLON
                  ( STAR | (contact_param (COMMA contact_param)*));
contact_param  :  (name_addr | addr_spec) (SEMI contact_params)*;
name_addr      :  ( display_name )? LAQUOT addr_spec RAQUOT;
addr_spec      :  SIP_URI | SIPS_URI | absoluteURI;
display_name   :  (token LWS)*/ quoted_string;

contact_params     :  c_p_q
                   |  c_p_expires
                   | contact_extension
                   ;

c_p_q              :  'q' EQUAL qvalue;
c_p_expires        :  'expires' EQUAL delta_seconds;
contact_extension  :  generic_param;
delta_seconds      :  (DIGIT)+;

Content_Disposition   :  'Content_Disposition' HCOLON
                         disp_type ( SEMI disp_param )*;
disp_type             :  'render'
                      |  'session'
                      |  'icon'
                      |  'alert'
                      |  disp_extension_token
                      ;

disp_param            :  handling_param
                      |  generic_param
                      ;

handling_param        :  'handling' EQUAL
                         ( 'optional' | 'required'
                         | other_handling )
                      ;

other_handling        :  token;
disp_extension_token  :  token ;

Content_Encoding  :  ( 'Content_Encoding' | 'e' ) HCOLON
                     content_coding *(COMMA content_coding);

Content_Language  :  'Content_Language' HCOLON
                     language_tag *(COMMA language_tag);
language_tag      :  primary_tag *( '-' subtag );
primary_tag       :  ALPHA{1-8};
subtag            :  ALPHA{1-8};

Content_Length  :  ( 'Content-Length' | 'l' ) HCOLON DIGIT+;
Content_Type     :  ( 'Content-Type' | 'c' ) HCOLON media_type;
media_type       :  m_type SLASH m_subtype (SEMI m_parameter)*;
m_type           :  discrete_type | composite_type;
discrete_type    :  'text'
                 |  'image'
                 |  'audio'
                 |  'video'
                 |  'application'
                 |  extension_token
                 ;

composite_type   :  'message'
                 |  'multipart'
                 |  extension_token
                 ;

extension_token  :  ietf_token
                 |  x_token
                 ;

ietf_token       :  token;
x_token          :  'x-' token;
m_subtype        :  extension_token
                 |  iana_token
                 ;

iana_token       :  token;
m_parameter      :  m_attribute EQUAL m_value;
m_attribute      :  token;
m_value          :  token
                 | quoted_string
                 ;

CSeq  :  'CSeq' HCOLON DIGIT+ LWS Method;

Date          :  'Date' HCOLON SIP_date;
SIP_date      :  rfc1123_date;
rfc1123_date  :  wkday ',' SP date1 SP time SP 'GMT';
date1         :  DIGIT{2} SP month SP DIGIT{4};
                 // day month year (e.g., 02 Jun 1982)
time          :  DIGIT{2} ':' DIGIT{2} ':' DIGIT{2};
                 // 00:00:00 - 23:59:59

wkday         :  'Mon'
              |  'Tue'
              |  'Wed'
              |  'Thu'
              |  'Fri'
              |  'Sat'
              |  'Sun'
              ;

month         :  'Jan'
              |  'Feb'
              |  'Mar'
              |  'Apr'
              |  'May'
              |  'Jun'
              |  'Jul'
              |  'Aug'
              |  'Sep'
              |  'Oct'
              |  'Nov'
              |  'Dec'
              ;

Error_Info  :  'Error-Info' HCOLON error_uri *(COMMA error_uri);

error_uri   :  LAQUOT absoluteURI RAQUOT *( SEMI generic_param );

Expires     :  'Expires' HCOLON delta_seconds;
From        :  ( 'From' | 'f' ) HCOLON from_spec;
from_spec   :  ( name_addr | addr_spec )
               *( SEMI from_param )
            ;
from_param  :  tag_param | generic_param;
tag_param   :  'tag' EQUAL token;

In_Reply_To  :  'In-Reply-To' HCOLON callid (COMMA callid)*;

Max_Forwards  :  'Max-Forwards' HCOLON DIGIT+;

MIME_Version  :  'MIME-Version' HCOLON DIGIT+ '.' DIGIT+;

Min_Expires  :  'Min-Expires' HCOLON delta_seconds;

Organization  :  'Organization' HCOLON (TEXT_UTF8_TRIM)?;

Priority        :  'Priority' HCOLON priority_value;
priority_value  :  'emergency'
                |  'urgent'
                |  'normal'
                |  'non-urgent'
                |  other_priority
                ;

other_priority  :  token;

Proxy_Authenticate  :  'Proxy-Authenticate' HCOLON challenge;
challenge           :  ('Digest' LWS digest_cln (COMMA digest_cln)*)
                    |  other_challenge
                    ;

other_challenge     :  auth_scheme LWS auth_param
                       (COMMA auth_param)*
                    ;
digest_cln          :  realm
                    |  domain
                    |  nonce
                    |  opaque
                    |  stale
                    |  algorithm
                    |  qop_options
                    |  auth_param
                    ;

realm               :  'realm' EQUAL realm_value;
realm_value         :  quoted_string;
domain              :  'domain' EQUAL LDQUOT URI
                       ( SP+ URI )* RDQUOT
                    ;

URI                 :  absoluteURI | abs_path;
nonce               :  'nonce' EQUAL nonce_value;
nonce_value         :  quoted_string;
opaque              :  'opaque' EQUAL quoted_string;
stale               :  'stale' EQUAL ( 'true' | 'false' );
algorithm           :  'algorithm' EQUAL ( 'MD5' | 'MD5-sess'
                       | token )
                    ;

qop_options         :  'qop' EQUAL LDQUOT qop_value
                       (',' qop_value)* RDQUOT
                    ;

qop_value           :  'auth' | 'auth-int' | token;


Proxy_Authorization  :  'Proxy-Authorization' HCOLON credentials;

Proxy_Require  :  'Proxy-Require' HCOLON option_tag
                  (COMMA option_tag)*
               ;

option_tag     :  token;

Record_Route  :  'Record-Route' HCOLON rec_route *(COMMA rec_route);
rec_route     :  name_addr ( SEMI rr_param )*;
rr_param      :  generic_param;

Reply_To      :  'Reply-To' HCOLON rplyto_spec;
rplyto_spec   :  ( name_addr | addr_spec )
                 ( SEMI rplyto_param )*
              ;

rplyto_param  :  generic_param;
Require       :  'Require' HCOLON option_tag *(COMMA option_tag);

Retry_After  :  'Retry-After' HCOLON delta_seconds
                ( comment )? ( SEMI retry_param )*
             ;

retry_param  :  ('duration' EQUAL delta_seconds)
             | generic_param
             ;


Route        :  'Route' HCOLON route_param *(COMMA route_param);
route_param  :  name_addr *( SEMI rr_param );

Server           :  'Server' HCOLON server_val *(LWS server_val);
server_val       :  product | comment;
product          :  token (SLASH product_version)?;
product_version  :  token;

Subject  :  ( 'Subject' | 's' ) HCOLON (TEXT_UTF8_TRIM)?;

Supported  :  ( 'Supported' | 'k' ) HCOLON
              (option_tag (COMMA option_tag)*)?
           ;

Timestamp  :  'Timestamp' HCOLON (DIGIT)+
               ( '.' (DIGIT)* )? ( LWS delay )?
           ;

delay      :  (DIGIT)* ( '.' (DIGIT)* )?;

To        :  ( 'To' | 't' ) HCOLON ( name_addr
             | addr_spec ) ( SEMI to_param )*
          ;

to_param  :  tag_param | generic_param;

Unsupported  :  'Unsupported' HCOLON option_tag (COMMA option_tag)*;
User_Agent  :  'User_Agent' HCOLON server_val (LWS server_val)*;

Via               :  ( 'Via' | 'v' ) HCOLON via_parm (COMMA via_parm)*;
via_parm          :  sent_protocol LWS sent_by ( SEMI via_params )*;
via_params        :  via_ttl
                  |  via_maddr
                  |  via_received
                  |  via_branch
                  | via_extension
                  ;

via_ttl           :  'ttl' EQUAL ttl;
via_maddr         :  'maddr' EQUAL host;
via_received      :  'received' EQUAL (IPv4address | IPv6address);
via_branch        :  'branch' EQUAL token;
via_extension     :  generic_param;
sent_protocol     :  protocol_name SLASH protocol_version
                     SLASH transport;
protocol_name     :  'SIP' | token;
protocol_version  :  token;
transport         :  'UDP'
                  |  'TCP'
                  |  'TLS'
                  |  'SCTP'
                  |  other_transport
                  ;

sent_by           :  host ( COLON port )?;
ttl               :  DIGIT{1-3} ; // 0 to 255

Warning        :  'Warning' HCOLON warning_value *(COMMA warning_value);
warning_value  :  warn_code SP warn_agent SP warn_text;
warn_code      :  DIGIT{3};
warn_agent     :  hostport | pseudonym;
                  //  the name or pseudonym of the server adding
                  //  the Warning header, for use in debugging
warn_text      :  quoted_string;
pseudonym      :  token;

WWW_Authenticate  :  'WWW_Authenticate' HCOLON challenge;

extension_header  :  header_name HCOLON header_value;
header_name       :  token;
header_value      :  (TEXT_UTF8char | UTF8_CONT | LWS)*;
message_body  :  OCTET*;
