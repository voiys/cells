;;;; session.lisp --- the servers a session's client hands it.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; An ACP client hands each session its own MCP servers in session/new
;;;; (T3 Code its `t3-code' server, a command with a per-thread token in its
;;;; env). The core holds them in memory and tells every function on
;;;; NLE::*SESSION-MCP-SERVERS-HOOKS* each time a session's list is set; this
;;;; cell's hook (SESSION-SERVERS-SET) is the only way they arrive here, and
;;;; nothing is read back at start.
;;;;
;;;; A session's servers live apart from the configured ones, in
;;;; *SESSION-SERVERS* by session id, each a SERVER whose spec carries that
;;;; id. An evaluation running in the session (NLK:*SCRIBE-SESSION-ID*) finds
;;;; them first, by name, ahead of a configured server of the same name; no
;;;; other session sees them. Nothing is generated for them -- a function
;;;; mcp:t3-code/... would be every session's -- so the model calls one by
;;;; name, (mcp:call "t3-code" "tool" ...). Each connects once it is handed,
;;;; keeps no catalog on disk, never signs in with OAuth, and writes its
;;;; stderr to a log whose name carries the session id. A list set again
;;;; keeps a server reached the same way, connection and all; one dropped or
;;;; changed is closed on a thread of its own, so the hook returns at once.
;;;;
;;;; The model learns of them from a live section (`mcp-session', advising
;;;; NLE::READ-LIVE-SECTIONS for the session asking): a short line naming
;;;; each server, its tools once a connect listed them, and the call form.
;;;; It rides only the session it is true of, so the standing prompt every
;;;; session shares does not move.

(in-package #:nodecode-mcp)

(defparameter *session-section-budget* 1500
  "Characters the `mcp-session' live section may take.")

(defun hooks-symbol ()
  "The core's NLE::*SESSION-MCP-SERVERS-HOOKS*, or NIL in a core without it."
  (let ((symbol (find-symbol "*SESSION-MCP-SERVERS-HOOKS*" '#:nodecode.evolved)))
    (and symbol (boundp symbol) symbol)))

(defun take-held-session-servers ()
  "Hold again every session's servers the core still holds: a cell that
starts again was told them before it stopped, and the client that handed
them sends them only on a new link. A core without the reader holds none."
  (let ((sessions (find-symbol "SESSION-MCP-SERVER-SESSIONS" '#:nodecode.evolved))
        (servers (find-symbol "SESSION-MCP-SERVERS" '#:nodecode.evolved)))
    (when (and sessions servers (fboundp sessions) (fboundp servers))
      (dolist (session-id (funcall sessions))
        (session-servers-set session-id (funcall servers session-id))))))

(defun close-servers (servers why)
  "Close SERVERS, each on a thread of its own, its call lock taken when it
comes within *STOP-LOCK-SECONDS*; WHY names the threads. => the threads."
  (loop for server in servers
        collect (let ((server server))
                  (set-state server :stopped)
                  (nlk:spawn (format nil "mcp-~a-~a" why (server-name server))
                    (let ((*close-grace-seconds* 1/4))
                      (unless (bt2:with-lock-held (server.call-lock :timeout *stop-lock-seconds*)
                                (close-client server)
                                t)
                        (warn "mcp ~a: busy at its close; closing its connection from outside"
                              (server-name server))
                        (close-client server)))))))

(defun session-server-specs (session-id specs)
  "SPECS, a session's list in ACP's shape, as SERVER-SPECs; a second server
of one name is refused."
  (let ((seen '()))
    (loop for entry in (coerce (or specs #()) 'list)
          for spec = (parse-session-entry session-id entry)
          collect (if (and (null spec.refusal) (member spec.name seen :test #'string=))
                      (make-server-spec :name spec.name :session-id session-id :literal-p t :enabled-p nil
                                        :refusal (format nil "a second session server named ~a" spec.name))
                      (progn (push spec.name seen) spec)))))

(defun session-servers-set (session-id specs)
  "The hook the core calls with SESSION-ID's servers: SPECS, ACP McpServer
objects, or NIL to drop them all. A server reached as before is kept, a new
one connects at once, and the rest are closed."
  (when (and *running* (stringp session-id))
    (let* ((wanted (session-server-specs session-id specs))
           (dropped '())
           (servers
             (sb-ext:with-locked-hash-table (*session-servers*)
               (let* ((old (gethash session-id *session-servers*))
                      (new (loop for spec in wanted
                                 collect (or (find-if (lambda (server) (same-reach-p server.spec spec)) old)
                                             (make-server :spec spec
                                                          :state (if spec.refusal :refused :disconnected)
                                                          :error-text spec.refusal)))))
                 (setf dropped (set-difference old new))
                 (if new
                     (setf (gethash session-id *session-servers*) new)
                     (remhash session-id *session-servers*))
                 new))))
      (when dropped (close-servers dropped "drop"))
      ;; ACP asks an agent to connect every server its client hands it, as
      ;; the Claude and Codex adapters do at once: a new one connects now, on
      ;; its own thread, and its tools reach the session's section.
      (dolist (server servers)
        (when (eq :disconnected server.state) (spawn-connect server :unless-ready t)))
      (length servers))))

(defun stop-session-servers ()
  "Close every session's servers and forget them; wait for the closes."
  (let ((servers (sb-ext:with-locked-hash-table (*session-servers*)
                   (prog1 (loop for list being the hash-values of *session-servers* append list)
                     (clrhash *session-servers*)))))
    (dolist (closer (close-servers servers "close"))
      (handler-case (bt2:join-thread closer)
        (error (condition) (warn "mcp: a session server's close failed: ~a" condition))))))

;;; --- what the model reads -------------------------------------------------------

(defun session-section-text (session-id)
  "The `mcp-session' live section for SESSION-ID: its servers, each one's
tools once listed, and how to call them; NIL when it has none."
  (nlk:when-let (servers (session-servers session-id))
    (let ((text (with-output-to-string (out)
                  (format out "This session's client gave it MCP servers of its own, reached by name only: ~
(mcp:call \"SERVER\" \"TOOL\" :arg value ...) calls a tool, (mcp:tools \"SERVER\") lists each tool's ~
arguments (connecting it first), (mcp:instructions \"SERVER\") reads its instructions, (mcp:status) says how each stands.")
                  (dolist (server servers)
                    (let* ((snapshot (server-snapshot server))
                           (tools (mapcar (lambda (tool) (getf tool :name)) (getf snapshot :tools)))
                           (instructions (getf snapshot :instructions)))
                      (cond (tools
                             (format out "~%  ~a: ~d tool~:p: ~{~a~^ ~}" (server-name server) (length tools) tools)
                             (when instructions
                               (format out "~%    instructions: ~:d characters - (mcp:instructions ~s)"
                                       (length instructions) (server-name server))))
                            ((eq (getf snapshot :state) :refused)
                             (format out "~%  ~a: refused (~a)" (server-name server)
                                     (nlk:one-line (or (getf snapshot :error) "") :cap 120)))
                            (t (format out "~%  ~a: connecting; its tools list once it is up"
                                       (server-name server)))))))))
      (nlk:clip text *session-section-budget* :disclose "(mcp:tools) lists them all"))))

(defun session-live-sections (next session-id)
  "NLE::READ-LIVE-SECTIONS, advised: SESSION-ID's own servers ride as its
`mcp-session' section."
  (let ((sections (funcall next session-id))
        (text (session-section-text session-id)))
    (if text
        (append (remove "mcp-session" sections :key #'car :test #'equal)
                (list (cons "mcp-session" text)))
        sections)))
