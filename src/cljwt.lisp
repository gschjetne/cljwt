;; Copyright © 2014 Grim Schjetne <grim@schjetne.se>

;; This file is part of CLJWT.

;; CLJWT is free software: you can redistribute it and/or modify
;; it under the terms of the GNU Lesser General Public License as
;; published by the Free Software Foundation, either version 3 of the
;; License, or (at your option) any later version.

;; CLJWT is distributed in the hope that it will be useful, but
;; WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
;; Lesser General Public License for more details.

;; You should have received a copy of the GNU Lesser General Public
;; License along with CLJWT.  If not, see
;; <http://www.gnu.org/licenses/>.

(in-package #:cl-user)
(defpackage #:cljws
  (:use #:cl
        #:cl-base64
        :ironclad)
  (:import-from #:alexandria
                #:plist-hash-table
                #:doplist)
  (:import-from #:flexi-streams
                #:string-to-octets
                #:octets-to-string)
  (:export #:issue
           #:to-unix-time))

(in-package #:cljws)

(defmacro bind-hash-tables (bindings &body body)
  `(let ,(loop for binding in bindings collect
              (list (car binding)
                    `(etypecase ,(cadr binding)
                       (hash-table ,(cadr binding))
                       (list (plist-hash-table ,(cadr binding)
                                               :test #'equal)))))
     ,@body))

(defmacro add-claims (hash &rest claims)
  `(progn ,@(loop for (key value) on claims by #'cddr collect
                 `(when ,value
                    (setf (gethash ,key ,hash) ,value)))))

(defun to-unix-time (time)
  "Convert universal time to New Jersey time"
  (when time (- time (encode-universal-time 0 0 0 1 1 1970 0))))


(defun base64 (input)
  "Takes a string, returns an unpadded URI-encoded Base64 string.
Necessary because CL-BASE64 has no option to omit padding."
  (with-output-to-string (out)
    (with-input-from-string
        (in
         (etypecase input
           (string (string-to-base64-string input :uri t))
           ((simple-array (unsigned-byte 8))
            (usb8-array-to-base64-string input :uri t))))
      (loop for character = (read-char in nil)
         while character do
           (unless (eq character #\.)
             (write-char character out))))))

(defun issue (claims &key algorithm secret issuer subject audience
                       expiration not-before issued-at id more-header)
  "Encodes and returns a JSON Web Token. Times are in universal-time,
number of seconds from 1900-01-01 00:00:00"
  (bind-hash-tables ((claimset claims)
                     (header more-header))
    ;; Add registered claims to the claims hash table
    (add-claims claimset
                "iss" issuer
                "sub" subject
                "aud" audience
                "exp" (to-unix-time expiration)
                "nbf" (to-unix-time not-before)
                "iat" (to-unix-time issued-at)
                "jti" id)
    ;; Add type and algorithm to the header hash table
    (add-claims header
                "typ" "JWT"
                "alg" (ecase algorithm
                        (:plain "plain")
                        (:hs256 "HS256")))
    ;; Prepare JSON and, if applicable, key
    (let ((header-string (base64
                          (with-output-to-string (s)
                            (yason:encode header s))))
          (claims-string (base64
                          (with-output-to-string (s)
                            (yason:encode claimset s))))
          (secret (unless (eq algorithm :plain)
                    (etypecase secret
                      ((simple-array (unsigned-byte 8))
                       secret)
                      (string
                       (string-to-octets secret
                                         :external-format :utf-8))))))
      ;; Assemble and, if applicable, sign the JWT
      (format nil "~A.~A.~@[~A~]"
              header-string
              claims-string
              (when (eq algorithm :hs256)
                (base64
                 (hmac-digest
                  (update-hmac (make-hmac secret 'SHA256)
                               (concatenate '(vector (unsigned-byte 8))
                                            (string-to-octets
                                             header-string)
                                            #(46) ; ASCII period (.)
                                            (string-to-octets
                                             claims-string))))))))))
