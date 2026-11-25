;;;; config.lisp --- the mcp section of the shared config, typed.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; The contract is the retired Zig client's, verbatim:
;;;;
;;;;   "mcp": {
;;;;     "servers": {
;;;;       "files":  {"command": "mcp-files", "args": ["--root", "/tmp"],
;;;;                  "env": {"K": "v"}, "timeout_ms": 30000},
;;;;       "remote": {"url": "https://host/mcp", "headers": {"Authorization": "..."}},
;;;;       "off":    {"command": "x", "enabled": false}
;;;;     },
;;;;     "inherit_env_allowlist": ["PATH", "HOME", ...]
;;;;   }
;;;;
;;;; A url without a command is streamable HTTP, anything else is stdio; an
;;;; explicit "transport" ("stdio" | "http" | "streamable-http", or an object
;;;; with that "type") wins. No cwd, no per-tool allow/deny. Header values
;;;; are secrets: nothing in this cell ever prints one; surfaces show a
;;;; count. A header or env value may name its secret rather than hold it
;;;; (references, below), so the config need carry none.
;;;;
;;;; An http server signs in with OAuth (oauth.lisp) unless it sends its own
;;;; Authorization header or says "oauth": false. "oauth" may instead be an
;;;; object of the settings a server needs, every member optional:
;;;;
;;;;   "oauth": {"client_id": "...", "client_secret": "${file:~/.secrets/x}",
;;;;             "scope": "read write", "callback_port": 33418,
;;;;             "client_registration": "auto" | "dcr" | "cimd",
;;;;             "auth_server_metadata_url": "https://as/.well-known/..."}
;;;;
;;;; Each entry validates on its own: a refused entry becomes a spec carrying
;;;; the refusal text (the server shows as `refused` in every status) and its
;;;; siblings still run. The kernel's typed accessors (nlk:config-*) signal
;;;; NLK:CONFIG-REFUSAL, which is the one condition caught here.

(in-package #:nodecode-mcp)

(defparameter +default-timeout-ms+ 30000
  "Per-request budget when an entry names none (the Zig default_call_timeout_ms).")

(defparameter +default-inherit-env+
  '("PATH" "HOME" "USER" "LANG" "LC_ALL" "LC_CTYPE" "TMPDIR" "TMP" "TEMP"
    "SHELL" "TERM" "COLORTERM" "NO_COLOR" "TZ")
  "Environment a child server inherits when the section names no allowlist.")

;;; The serving image's own fd 2 is severed to a log while a TUI owns the
;;; terminal, so a child must never inherit it; a file the operator can name
;;; beats /dev/null when a server dies at startup.
(nlk:define-startup-parameter *log-directory*
  (nlk:home "mcp/")
  "Where a stdio server's stderr lands, one append-only file per server.")

(defstruct (server-spec (:copier nil))
  "One validated mcp.servers entry."
  (name "" :type string)
  (transport :stdio :type keyword)    ; :stdio | :http
  (command nil)                       ; string, stdio
  (args '() :type list)               ; strings, stdio
  (env '() :type list)                ; ((name . value) ...), stdio
  (url nil)                           ; string, http
  (headers '() :type list)            ; ((name . value) ...), http
  (oauth '())                         ; :off, or a plist of the oauth settings, http
  (timeout-ms +default-timeout-ms+ :type integer)
  (enabled-p t)
  (lazy-p t)                          ; started by its first call when a catalog is kept
  (refusal nil)                       ; config-refusal text, or NIL
  (session-id nil)                    ; the session whose client handed it over (session.lisp), or NIL
  (literal-p nil))                    ; env and header values are values, never references

(nlk:access (spec server-spec))

;;; A spec holds env and header values, or references to them: printed, it
;;; shows how the server is reached and a count of each, never one of them.
(defmethod print-object ((spec server-spec) stream)
  (print-unreadable-object (spec stream :type t :identity t)
    (format stream "~a~@[ of session ~a~] ~a~@[ (~d env)~]"
            (server-spec-name spec) (server-spec-session-id spec)
            (if (server-spec-refusal spec) "refused" (ignore-errors (transport-text spec)))
            (let ((count (length (server-spec-env spec)))) (and (plusp count) count)))))

(defun string-alist (section key)
  "KEY's object as ((name . value) ...) with string values, or '() when absent."
  (multiple-value-bind (value present) (nlk::section-value section key)
    (cond ((not present) '())
          ((hash-table-p value)
           (sort (loop for name being the hash-keys of value using (hash-value entry)
                       do (unless (stringp entry)
                            (nlk:config-error "~a.~a must be a string, got ~s" key name entry))
                       collect (cons name entry))
                 #'string< :key #'car))
          (t (nlk:config-error "~a must be an object, got ~s" key value)))))

;;; --- references -------------------------------------------------------------
;;;
;;; A header or env value may name its secret rather than hold it:
;;;
;;;   "Authorization": "Bearer ${GITHUB_TOKEN}"          a variable of this process
;;;   "Authorization": "Bearer ${env:GITHUB_TOKEN}"      the same
;;;   "Authorization": "Bearer ${file:~/.secrets/gh}"    a file's text, trimmed
;;;
;;; ${NAME} is how Claude Code's .mcp.json and trellage write one. The spec
;;; keeps the reference and each connect resolves it afresh, so a rotated
;;; secret takes the next reconnect and the value lives only in the
;;; transport: never in a spec, a status or a refusal. A background
;;; gateway's unit passes none of a shell's variables; ${file:...} is the
;;; reference that reaches it.

(nlk:define-error reference-unresolved (error) (detail)
  ;; A report function, not a format string: a string's DETAIL stands for the
  ;; slot's reader, and an image of the release before this one, taking the
  ;; release live, refuses a form that names a reader only the form defines.
  (:report (lambda (condition stream) (format stream "~a" (slot-value condition 'detail))))
  (:documentation "A reference names a variable that is unset or empty, or a
file that cannot be read: DETAIL names the reference, never a value."))

(defun variable-name-p (text)
  "Whether TEXT is a variable name: [A-Za-z_][A-Za-z0-9_]*."
  (and (plusp (length text))
       (not (digit-char-p (char text 0)))
       (every (lambda (char) (or (char= char #\_) (char<= #\a char #\z)
                                 (char<= #\A char #\Z) (char<= #\0 char #\9)))
              text)))

(defun parse-reference (inner where)
  "(:env NAME INNER) or (:file PATH INNER) for INNER, the text between ${ and }."
  (flet ((refuse ()
           (nlk:config-error "~a: ${~a} is not a reference this client reads: ${NAME}, ${env:NAME} or ${file:PATH}"
                             where inner)))
    (cond ((variable-name-p inner) (list :env inner inner))
          ((uiop:string-prefix-p "env:" inner)
           (if (variable-name-p (subseq inner 4)) (list :env (subseq inner 4) inner) (refuse)))
          ((uiop:string-prefix-p "file:" inner)
           (let ((path (subseq inner 5)))
             ;; The gateway's working directory is nobody's choice: no relative path.
             (unless (or (uiop:string-prefix-p "~/" path)
                         (uiop:absolute-pathname-p (ignore-errors (uiop:parse-native-namestring path))))
               (nlk:config-error "~a: ${~a} needs an absolute path or one under ~~/" where inner))
             (list :file path inner)))
          (t (refuse)))))

(defun reference-pieces (text where &aux (pieces '()) (start 0))
  "TEXT as its pieces: literal strings, and a PARSE-REFERENCE list for each
${...}. WHERE (\"headers.Authorization\") heads a config refusal."
  (loop
    (let ((open (search "${" text :start2 start)))
      (unless open
        (when (< start (length text)) (push (subseq text start) pieces))
        (return (nreverse pieces)))
      ;; Only the reference is ever quoted: an unclosed ${ may be a literal secret's.
      (let ((close (or (position #\} text :start open)
                       (nlk:config-error "~a: a ${ is unclosed" where))))
        (when (< start open) (push (subseq text start open) pieces))
        (push (parse-reference (subseq text (+ open 2) close) where) pieces)
        (setf start (1+ close))))))

(defun checked-references (alist key)
  "ALIST, the ((name . value) ...) of KEY (\"headers\", \"env\"), once every
reference in its values parses."
  (dolist (pair alist alist)
    (reference-pieces (cdr pair) (format nil "~a.~a" key (car pair)))))

(defun reference-path (path)
  "PATH as a pathname, a leading ~/ read as the home."
  (uiop:parse-native-namestring
   (if (uiop:string-prefix-p "~/" path)
       (concatenate 'string (uiop:native-namestring (user-homedir-pathname)) (subseq path 2))
       path)))

(defun reference-value (piece where one-line)
  "What PIECE names, trimmed; REFERENCE-UNRESOLVED when it names nothing,
holds a NUL, or (ONE-LINE, a header's rule) a line break."
  (destructuring-bind (kind name inner) piece
    (flet ((unresolved (control &rest arguments)
             (error 'reference-unresolved :detail (format nil "~a: ~?" where control arguments))))
      (let* ((raw (ecase kind
                    (:env (uiop:getenv name))
                    (:file (handler-case (uiop:read-file-string (reference-path name))
                             (error (condition)
                               (unresolved "cannot read ${~a}: ~a" inner condition))))))
             (value (and raw (nlk:trimmed raw))))
        (cond ((null raw) (unresolved "${~a} is unset" inner))
              ((zerop (length value)) (unresolved "${~a} is empty" inner))
              ((find (code-char 0) value) (unresolved "${~a} holds a NUL" inner))
              ((and one-line (find-if (lambda (char) (member char '(#\Return #\Newline))) value))
               (unresolved "${~a} holds a line break" inner))
              (t value))))))

(defun resolve-references (text where &key (one-line t))
  "TEXT with each reference in it replaced by what it names. WHERE heads a
refusal; ONE-LINE, a header's rule, refuses a value holding a line break."
  (if (search "${" text)
      (format nil "~{~a~}" (mapcar (lambda (piece)
                                     (if (stringp piece) piece (reference-value piece where one-line)))
                                   (reference-pieces text where)))
      text))

(defun resolved-alist (alist key &key (one-line t))
  "ALIST, the ((name . value) ...) of KEY, with every value's references resolved."
  (mapcar (lambda (pair)
            (cons (car pair)
                  (resolve-references (cdr pair) (format nil "~a.~a" key (car pair)) :one-line one-line)))
          alist))

(defun parse-oauth (entry)
  "The `oauth' member of ENTRY: :OFF for false, else the plist of its
settings (:CLIENT-ID :CLIENT-SECRET :SCOPE :CALLBACK-PORT
:CLIENT-REGISTRATION :AUTH-SERVER-METADATA-URL), '() when absent."
  (multiple-value-bind (value present) (nlk::section-value entry "oauth")
    (cond ((or (not present) (eq value :null) (eq value t)) '())
          ((null value) :off)
          ((not (hash-table-p value))
           (nlk:config-error "oauth must be false or an object, got ~s" value))
          (t
           (let ((port (nlk:config-integer value "callback_port" 0))
                 (registration (or (nlk:config-string value "client_registration") "auto"))
                 (metadata-url (nlk:config-string value "auth_server_metadata_url"))
                 (secret (nlk:config-string value "client_secret")))
             (unless (<= 0 port 65535)
               (nlk:config-error "oauth.callback_port must be a port, got ~a" port))
             (unless (member registration '("auto" "dcr" "cimd") :test #'string-equal)
               (nlk:config-error "oauth.client_registration must be auto, dcr or cimd, got ~s"
                                 registration))
             (unless (or (null metadata-url) (uiop:string-prefix-p "https://" metadata-url)
                         (uiop:string-prefix-p "http://127.0.0.1" metadata-url)
                         (uiop:string-prefix-p "http://localhost" metadata-url))
               (nlk:config-error "oauth.auth_server_metadata_url must be https"))
             ;; A secret may be a reference, checked here and resolved at use.
             (when secret (reference-pieces secret "oauth.client_secret"))
             (list :client-id (nlk:config-string value "client_id")
                   :client-secret secret
                   :scope (nlk:config-string value "scope")
                   :callback-port (and (plusp port) port)
                   :client-registration (intern (string-upcase registration) :keyword)
                   :auth-server-metadata-url metadata-url))))))

(defun parse-server-entry (name entry &optional (lazy-default t))
  "A SERVER-SPEC for ENTRY, or one carrying the refusal text. LAZY-DEFAULT is
the section's `lazy', what an entry that names none gets."
  (nlk:with-handlers ((nlk:config-refusal (condition)
                        (make-server-spec :name (if (stringp name) name (princ-to-string name))
                                          :enabled-p nil
                                          :refusal (princ-to-string condition))))
    ;; [A-Za-z0-9_-]+: what a generated symbol and a log file name can carry.
    (unless (and (stringp name)
                 (plusp (length name))
                 (every (lambda (char) (or (alphanumericp char) (find char "_-"))) name))
      (nlk:config-error "server name ~s: only letters, digits, _ and -" name))
    (unless (hash-table-p entry)
      (nlk:config-error "server ~a must be an object" name))
    (let* ((command (nlk:config-string entry "command"))
           (url (nlk:config-string entry "url"))
           ;; An explicit transport (a string, or an object with that type) wins.
           (transport (multiple-value-bind (value present) (nlk::section-value entry "transport")
                        (if (not present)
                            (if (and url (null command)) :http :stdio)
                            (let ((type (cond ((stringp value) value)
                                              ((hash-table-p value) (nlk:config-string value "type"))
                                              (t (nlk:config-error
                                                  "transport must be a string or an object, got ~s"
                                                  value)))))
                              (cond ((member type '("stdio") :test #'string-equal) :stdio)
                                    ((member type '("http" "streamable-http" "streamable_http")
                                             :test #'string-equal)
                                     :http)
                                    (t (nlk:config-error
                                        "transport must be stdio or http, got ~s" type))))))))
      (ecase transport
        (:stdio
         (unless command
           (nlk:config-error "server ~a: stdio needs a command" name)))
        (:http
         (unless (and url (or (uiop:string-prefix-p "http://" url)
                              (uiop:string-prefix-p "https://" url)))
           (nlk:config-error "server ~a: http needs an http(s) url" name))))
      (make-server-spec
       :name name
       :transport transport
       :command command
       :args (nlk:config-string-list entry "args")
       :env (checked-references (string-alist entry "env") "env")
       :url url
       :headers (checked-references (string-alist entry "headers") "headers")
       :oauth (if (eq transport :http) (parse-oauth entry) '())
       :timeout-ms (let ((value (nlk:config-integer entry "timeout_ms" 0)))
                     (cond ((zerop value) +default-timeout-ms+)
                           ((minusp value)
                            (nlk:config-error "timeout_ms must be positive, got ~a" value))
                           (t value)))
       :enabled-p (nlk:config-boolean entry "enabled" t)
       :lazy-p (nlk:config-boolean entry "lazy" lazy-default)))))

(defun parse-mcp-section (section)
  "(values SPECS ALLOWLIST): the servers of SECTION in name order, each its
own validation, and the env allowlist."
  ;; A missing or non-object section is no servers at all.
  (if (hash-table-p section)
      (let ((servers (gethash "servers" section))
            (allowlist
              (if (nth-value 1 (nlk::section-value section "inherit_env_allowlist"))
                  (handler-case
                      (nlk:config-string-list section "inherit_env_allowlist")
                    (nlk:config-refusal (condition)
                      (warn "mcp: ~a; using the default allowlist" condition)
                      +default-inherit-env+))
                  +default-inherit-env+)))
        (values
         (when (hash-table-p servers)
           (mapcar (let ((lazy (handler-case (nlk:config-boolean section "lazy" t)
                                 (nlk:config-refusal (condition)
                                   (warn "mcp: ~a; servers start lazily" condition)
                                   t))))
                     (lambda (name) (parse-server-entry name (gethash name servers) lazy)))
                   (sort (loop for name being the hash-keys of servers collect name)
                         #'string<)))
         allowlist))
      (values '() +default-inherit-env+)))

(defun spec-alist (spec key)
  "SPEC's env (KEY \"env\") or headers (\"headers\") as the values a connect
sends: a session server's as its client gave them, a configured one's with
every reference resolved."
  (let ((alist (if (string= key "env") spec.env spec.headers)))
    (if spec.literal-p
        alist
        (resolved-alist alist key :one-line (string= key "headers")))))

(defun child-environment (spec allowlist &aux (env (spec-alist spec "env")))
  "The child's whole environment as \"NAME=VALUE\" strings: the allowlisted
variables that exist here (exported shell functions, the \"() {\" values,
skipped as the reference SDK skips them), then the entry's env on top, its
references resolved."
  (mapcar (lambda (pair) (format nil "~a=~a" (car pair) (cdr pair)))
          (append (loop for name in allowlist
                        for value = (uiop:getenv name)
                        when (and value (not (uiop:string-prefix-p "() {" value))
                                  (not (assoc name env :test #'string=)))
                          collect (cons name value))
                  env)))

(defun file-stem (spec-or-name)
  "The stem of a configured server's files, its name; a session server's
carries its session id ahead of it, both folded to what a file name holds."
  (flet ((safe (text)
           (substitute-if-not #\_ (lambda (char) (or (alphanumericp char) (find char "-_."))) text)))
    (if (and (server-spec-p spec-or-name) (server-spec-session-id spec-or-name))
        (format nil "session-~a--~a" (safe (server-spec-session-id spec-or-name))
                (safe (server-spec-name spec-or-name)))
        (safe (if (server-spec-p spec-or-name) (server-spec-name spec-or-name) spec-or-name)))))

(defun stderr-log-path (spec-or-name)
  "Where the process of SPEC-OR-NAME -- a spec, or a configured server's name
-- writes its stderr."
  (merge-pathnames (format nil "~a.stderr.log" (file-stem spec-or-name)) *log-directory*))

(defun transport-text (spec)
  "The transport for a status line: the command or the url, a header count
and never a header value."
  (ecase spec.transport
    (:stdio (format nil "stdio ~a~{ ~a~}"
                    spec.command spec.args))
    (:http (let ((count (length spec.headers)))
             (format nil "http ~a~@[ (~d header~:p)~]" spec.url (and (plusp count) count))))))

(defun oauth-enabled-p (spec)
  "Whether SPEC signs in with OAuth: an http server that sends no
Authorization header of its own and does not say oauth: false."
  (and (eq spec.transport :http)
       (not (eq spec.oauth :off))
       (not (assoc "authorization" spec.headers :test #'string-equal))))

;;; --- a session's servers ------------------------------------------------------
;;; An ACP client hands a session its own servers (session.lisp) in ACP's
;;; McpServer shape, passed through by the core unchanged:
;;;
;;;   {"name": S, "command": S, "args": [S...], "env": [{"name": S, "value": S}...]}
;;;   {"type": "http", "name": S, "url": S, "headers": [{"name": S, "value": S}...]}
;;;
;;; Its env and header values are the client's own secrets, carried as they
;;; are (LITERAL-P): no reference is read in them, and no refusal, status or
;;; log line quotes one. It never signs in with OAuth here, and keeps nothing
;;; on disk but its stderr log.

(defun pair-alist (pairs key)
  "PAIRS, ACP's [{name, value}...] under KEY, as ((name . value) ...)."
  (cond ((or (null pairs) (eq pairs :null)) '())
        ((not (and (vectorp pairs) (not (stringp pairs))))
         (nlk:config-error "~a must be an array of {name, value}" key))
        (t (loop for pair across pairs
                 for name = (nlk:json-value pair :text "name")
                 for value = (nlk:json-value pair :string "value")
                 unless (and name value)
                   do (nlk:config-error "every ~a entry needs a name and a string value" key)
                 collect (cons name value)))))

(defun parse-session-entry (session-id entry)
  "A SERVER-SPEC for ENTRY, one of SESSION-ID's servers in ACP's shape, or
one carrying the refusal text."
  (let ((name (nlk:json-value entry :text "name")))
    (nlk:with-handlers ((nlk:config-refusal (condition)
                          (make-server-spec :name (or name "?") :session-id session-id :literal-p t
                                            :enabled-p nil :refusal (princ-to-string condition))))
      (unless (hash-table-p entry)
        (nlk:config-error "a session server must be an object"))
      (unless name
        (nlk:config-error "a session server needs a name"))
      (let ((type (or (nlk:json-value entry :string "type") "stdio")))
        (cond
          ((string-equal type "stdio")
           (let ((command (nlk:json-value entry :text "command"))
                 (args (nlk:json-value entry :array "args")))
             (unless command
               (nlk:config-error "session server ~a: stdio needs a command" name))
             (unless (every #'stringp (or args #()))
               (nlk:config-error "session server ~a: args must be strings" name))
             (make-server-spec :name name :session-id session-id :literal-p t :transport :stdio
                               :command command :args (coerce (or args #()) 'list)
                               :env (pair-alist (gethash "env" entry) "env")
                               :oauth :off :lazy-p nil)))
          ((string-equal type "http")
           (let ((url (nlk:json-value entry :text "url")))
             (unless (and url (or (uiop:string-prefix-p "http://" url) (uiop:string-prefix-p "https://" url)))
               (nlk:config-error "session server ~a: http needs an http(s) url" name))
             (make-server-spec :name name :session-id session-id :literal-p t :transport :http
                               :url url :headers (pair-alist (gethash "headers" entry) "headers")
                               :oauth :off :lazy-p nil)))
          (t (nlk:config-error "session server ~a: transport ~a is not one this client speaks (stdio, http)"
                               name type)))))))

(defun same-reach-p (one other)
  "Whether the specs ONE and OTHER reach the same server the same way, every
env and header value included."
  (and (eq (server-spec-transport one) (server-spec-transport other))
       (every (lambda (read) (equal (funcall read one) (funcall read other)))
              (list #'server-spec-name #'server-spec-command #'server-spec-args #'server-spec-env
                    #'server-spec-url #'server-spec-headers #'server-spec-refusal))))
